"""Git + host-CLI plumbing for the ``pipeline_check fix-pr`` subcommand.

``fix-pr`` runs a scan, applies the autofixers (the same engine behind
``--fix --apply``), and then turns the patched working tree into a pull
/ merge request: a new branch, a commit of the changed files, a push,
and a PR opened via the host's tooling.

This module is the host-interaction half. The scan + autofix half lives
in ``cli.py`` (it reuses ``core.autofix`` and the existing apply
helpers). Everything here is a thin subprocess wrapper so the command
flow stays mockable in tests, matching the convention in
``core/diff.py``.

Host coverage:

- **GitHub** (``github.com`` or GitHub Enterprise remotes): the branch
  is pushed, then ``gh pr create`` opens the PR. Falls back to printing
  the compare URL when the ``gh`` CLI is absent.
- **GitLab** (``gitlab.com`` or self-hosted): the MR is created by the
  push itself via GitLab's ``-o merge_request.*`` push options, so no
  extra token or CLI is needed.
- **Other** (Bitbucket, unknown remotes): the branch is pushed and the
  user is told to open the request by hand. No silent failure.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

_GIT_TIMEOUT = 30

#: Host platforms fix-pr knows how to open a request on. ``unknown``
#: means "push the branch, then print manual instructions".
GITHUB = "github"
GITLAB = "gitlab"
BITBUCKET = "bitbucket"
UNKNOWN = "unknown"


class GitError(RuntimeError):
    """A git / host-CLI call failed in a way fix-pr can't recover from."""


def _reject_dash_prefix(name: str, value: str) -> None:
    """Reject a value that would smuggle a flag into git.

    git treats any argv element starting with ``-`` as an option even in
    a positional slot, so a branch / ref named ``--upload-pack=...`` is a
    command-injection vector. Reject at the boundary (mirrors the guard
    in ``core/diff.py``).
    """
    if value.startswith("-"):
        raise ValueError(
            f"{name} cannot start with '-' "
            f"(would smuggle a git flag into a positional argument); "
            f"got {value!r}"
        )


def _run(
    args: list[str],
    *,
    cwd: str = ".",
    timeout: int = _GIT_TIMEOUT,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess, translating failures into :class:`GitError`.

    No shell, argv-list only, so values never go through a shell parser.
    A missing executable (git / gh not installed) and a timeout both
    surface as ``GitError`` so the caller has one exception type to
    handle. With ``check=False`` a non-zero exit is returned to the
    caller instead of raised (used for boolean probes like
    "does this branch exist").
    """
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError(f"{args[0]!r} is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(
            f"{' '.join(args)} timed out after {timeout}s"
        ) from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise GitError(
            f"`{' '.join(args)}` failed (exit {result.returncode})"
            + (f": {detail}" if detail else "")
        )
    return result


# ── repository state ──────────────────────────────────────────────────────


def repo_root(cwd: str = ".") -> str | None:
    """Return the git repo top, or ``None`` when *cwd* isn't in a repo."""
    try:
        result = _run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd, check=False,
        )
    except GitError:
        return None
    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    return top or None


def is_dirty(cwd: str = ".") -> bool:
    """Return ``True`` when the working tree has uncommitted changes.

    Uses ``git status --porcelain``; any non-empty output (tracked
    modifications, staged changes, untracked files) counts as dirty.
    fix-pr refuses to run on a dirty tree by default so the autofix
    commit never sweeps in unrelated edits.
    """
    result = _run(["git", "status", "--porcelain"], cwd=cwd)
    return bool(result.stdout.strip())


def current_branch(cwd: str = ".") -> str:
    """Return the current branch name (the fix-pr base by default).

    On a detached HEAD git prints ``HEAD``; the caller should require an
    explicit ``--base`` in that case.
    """
    result = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
    return result.stdout.strip()


def branch_exists(name: str, cwd: str = ".") -> bool:
    """Return ``True`` when a local branch *name* already exists."""
    _reject_dash_prefix("branch", name)
    result = _run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"],
        cwd=cwd,
        check=False,
    )
    return result.returncode == 0


def unique_branch_name(base_name: str, cwd: str = ".") -> str:
    """Return *base_name*, or ``<base_name>-N`` if it's already taken.

    Lets ``fix-pr`` run repeatedly without clobbering or colliding with
    an earlier autofix branch the user hasn't merged yet.
    """
    _reject_dash_prefix("branch", base_name)
    if not branch_exists(base_name, cwd):
        return base_name
    suffix = 2
    while branch_exists(f"{base_name}-{suffix}", cwd):
        suffix += 1
    return f"{base_name}-{suffix}"


def checkout_new_branch(name: str, cwd: str = ".") -> None:
    """Create and switch to a new branch off the current HEAD."""
    _reject_dash_prefix("branch", name)
    _run(["git", "checkout", "-b", name], cwd=cwd)


def checkout(name: str, cwd: str = ".") -> None:
    """Switch to an existing branch."""
    _reject_dash_prefix("branch", name)
    _run(["git", "checkout", name], cwd=cwd)


def commit(
    paths: list[str], title: str, body: str, cwd: str = ".",
) -> None:
    """Stage *paths* and commit them with *title* / *body*.

    Only the listed paths are staged (``git add -- <paths>``), so even
    under ``--allow-dirty`` the commit is scoped to the autofix edits.
    The ``--`` separator stops git from treating a path as a flag.
    """
    _run(["git", "add", "--", *paths], cwd=cwd)
    args = ["git", "commit", "-m", title]
    if body:
        args += ["-m", body]
    _run(args, cwd=cwd)


# ── remote / host detection ─────────────────────────────────────────────────


def remote_url(remote: str, cwd: str = ".") -> str | None:
    """Return the URL configured for *remote*, or ``None`` if unset."""
    _reject_dash_prefix("remote", remote)
    result = _run(
        ["git", "remote", "get-url", remote], cwd=cwd, check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def detect_platform(url: str | None) -> str:
    """Classify a remote URL as github / gitlab / bitbucket / unknown.

    Host-substring match on the URL. Catches both SSH
    (``git@github.com:o/r.git``) and HTTPS forms, plus self-hosted
    instances whose host contains the vendor name (the common
    ``gitlab.example.com`` convention). An unrecognized host returns
    ``unknown`` and the caller degrades to push-and-instruct.
    """
    if not url:
        return UNKNOWN
    lowered = url.lower()
    if "github" in lowered:
        return GITHUB
    if "gitlab" in lowered:
        return GITLAB
    if "bitbucket" in lowered:
        return BITBUCKET
    return UNKNOWN


# ── push / open request ─────────────────────────────────────────────────────


def push(
    remote: str,
    branch: str,
    cwd: str = ".",
    *,
    push_options: tuple[str, ...] = (),
) -> None:
    """Push *branch* to *remote*, setting upstream tracking.

    *push_options* are forwarded as ``-o`` flags; GitLab reads
    ``merge_request.*`` options here to create the MR as a side effect
    of the push.
    """
    _reject_dash_prefix("remote", remote)
    _reject_dash_prefix("branch", branch)
    args = ["git", "push", "--set-upstream"]
    for opt in push_options:
        args += ["-o", opt]
    args += [remote, branch]
    # A push can legitimately take a while on a slow link; give it more
    # headroom than a local git query.
    _run(args, cwd=cwd, timeout=120)


def gitlab_push_options(
    base: str, title: str, *, remove_source_branch: bool = True,
) -> tuple[str, ...]:
    """Build the GitLab ``merge_request.*`` push options.

    These create the MR during the push (no API token or ``glab``
    needed). The description is intentionally omitted: push-option
    values are single-line, so the richer body is GitHub-only and a
    GitLab MR carries the title plus a pointer to edit it.
    """
    _reject_dash_prefix("base", base)
    opts = [
        "merge_request.create",
        f"merge_request.target={base}",
        f"merge_request.title={title}",
    ]
    if remove_source_branch:
        opts.append("merge_request.remove_source_branch")
    return tuple(opts)


def gh_available(cwd: str = ".") -> bool:
    """Return ``True`` when the GitHub ``gh`` CLI is callable."""
    try:
        result = _run(["gh", "--version"], cwd=cwd, check=False)
    except GitError:
        return False
    return result.returncode == 0


def gh_create_pr(
    base: str, head: str, title: str, body: str, cwd: str = ".",
) -> str:
    """Open a GitHub PR via ``gh pr create``; return the PR URL.

    Assumes the *head* branch is already pushed. ``gh`` prints the new
    PR's URL on stdout, which is returned verbatim for the summary line.
    """
    _reject_dash_prefix("base", base)
    _reject_dash_prefix("head", head)
    result = _run(
        [
            "gh", "pr", "create",
            "--base", base,
            "--head", head,
            "--title", title,
            "--body", body,
        ],
        cwd=cwd,
        timeout=60,
    )
    return result.stdout.strip()


# ── PR text ─────────────────────────────────────────────────────────────────


def default_title(check_ids: list[str]) -> str:
    """Build a one-line commit / PR title from the fixed check IDs."""
    n = len(check_ids)
    rule_word = "rule" if n == 1 else "rules"
    return f"fix: apply pipeline-check autofixes ({n} {rule_word})"


def build_body(
    check_ids: list[str], file_count: int, safety: str,
) -> str:
    """Build the PR / commit body listing what the autofixers changed.

    Markdown, since both ``gh`` PR bodies and git trailers render it
    fine. Lists the distinct check IDs remediated and the file count so
    a reviewer sees the scope without reading the diff first.
    """
    file_word = "file" if file_count == 1 else "files"
    lines = [
        f"Applied `pipeline-check` **{safety}** autofixes to "
        f"{file_count} {file_word}.",
        "",
        "Remediated checks:",
    ]
    lines += [f"- `{cid}`" for cid in check_ids]
    lines += [
        "",
        "Generated by `pipeline_check fix-pr`. Review the diff before "
        "merging: autofixers are conservative but operate on text, not "
        "the resolved config graph.",
    ]
    return "\n".join(lines)


@dataclass
class FixPrResult:
    """Outcome of a fix-pr submission, for the CLI summary line."""

    branch: str
    base: str
    platform: str
    file_count: int
    check_ids: list[str] = field(default_factory=list)
    pushed: bool = False
    pr_url: str | None = None
    #: Human-readable next-step note when no PR was opened automatically
    #: (``--no-push``, an unknown host, or a missing ``gh``).
    note: str | None = None
