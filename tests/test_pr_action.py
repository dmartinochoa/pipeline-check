"""Integration tests for the pipeline-check-pr GitHub Action entrypoint.

The action's :file:`entrypoint.py` shells out to ``gh api`` for every
external interaction. We replace ``subprocess.run`` with a fake
recorder so the test sees every API call without touching the
network.

Coverage:
  - per-finding mode posts one review comment per matching diff line
  - findings outside the PR diff land in the summary fallback
  - re-run with a known marker patches instead of duplicating
  - missing line precision routes to summary
  - read-only token / API failure routes to step summary
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parent.parent
_ENTRYPOINT_PATH = (
    _REPO / ".github" / "actions" / "pipeline-check-pr" / "entrypoint.py"
)


def _load_entrypoint():
    """Import entrypoint.py as a module without polluting sys.modules
    (its argparse-free, side-effect-light, but importing twice with
    different env vars wouldn't pick up the new env)."""
    spec = importlib.util.spec_from_file_location(
        "pipeline_check_pr_entrypoint", _ENTRYPOINT_PATH,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Recorder ─────────────────────────────────────────────────────────


class FakeProcess:
    """Drop-in for ``subprocess.run``. Records calls, replays scripted
    outputs.

    Construct with a list of ``(matcher, response)`` pairs where
    ``matcher`` is a substring tested against the joined command, and
    ``response`` is a ``(returncode, stdout, stderr)`` tuple. The
    first matching pair wins.
    """

    def __init__(
        self,
        responses: list[tuple[str, tuple[int, str, str]]] | None = None,
    ) -> None:
        self.responses = responses or []
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):  # noqa: D401, mimics subprocess.run
        self.calls.append(list(argv))
        joined = " ".join(str(a) for a in argv)
        for matcher, (rc, out, err) in self.responses:
            if matcher in joined:
                if rc != 0 and kwargs.get("check"):
                    raise __import__("subprocess").CalledProcessError(
                        rc, argv, out, err,
                    )
                return SimpleNamespace(returncode=rc, stdout=out, stderr=err)
        # Default: succeed silently.
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _scanner_response(findings: list[dict[str, Any]]) -> tuple[int, str, str]:
    payload = {"findings": findings, "schema_version": "1.1"}
    return 0, json.dumps(payload), ""


# ── Common test scaffolding ──────────────────────────────────────────


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Set the env vars the action's runner exports."""
    monkeypatch.setenv("PIPELINE_CHECK_PIPELINE", "github")
    monkeypatch.setenv("PIPELINE_CHECK_PATH", ".github/workflows")
    monkeypatch.setenv("PIPELINE_CHECK_SEVERITY", "MEDIUM")
    monkeypatch.setenv("PIPELINE_CHECK_RESOLVE_REMOTE", "false")
    monkeypatch.setenv("PIPELINE_CHECK_COMMENT_MODE", "per-finding")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/repo")
    monkeypatch.setenv("GITHUB_PR_NUMBER", "42")
    monkeypatch.setenv("GITHUB_HEAD_SHA", "deadbeef" * 5)
    summary_file = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    output_file = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    return SimpleNamespace(
        summary_file=summary_file,
        output_file=output_file,
    )


def _gh_pr_files_response(*entries: tuple[str, str]) -> str:
    """Build a fake ``gh api repos/.../pulls/n/files`` payload.

    Each entry is ``(filename, patch)``.
    """
    return json.dumps([
        {"filename": fn, "patch": patch} for fn, patch in entries
    ])


# ── Tests ────────────────────────────────────────────────────────────


def test_per_finding_mode_posts_one_review_comment_per_match(
    monkeypatch, env,
):
    findings = [
        {
            "check_id": "GHA-001", "title": "Pin actions",
            "severity": "HIGH", "passed": False,
            "description": "actions/checkout@v4 is unpinned",
            "recommendation": "Pin to a SHA",
            "resource": ".github/workflows/release.yml",
            "locations": [
                {"path": ".github/workflows/release.yml",
                 "start_line": 11, "end_line": 11},
            ],
        },
    ]
    fake = FakeProcess([
        ("pipeline_check", _scanner_response(findings)),
        ("repos/acme/repo/pulls/42/files",
         (0, _gh_pr_files_response(
             (".github/workflows/release.yml",
              "@@ -10,3 +10,5 @@\n line\n+uses: actions/checkout@v4\n+next\n line\n"),
         ), "")),
        # No prior review comments.
        ("repos/acme/repo/pulls/42/comments",
         (0, "[]", "")),
        # No prior issue comments.
        ("repos/acme/repo/issues/42/comments",
         (0, "[]", "")),
    ])
    monkeypatch.setattr("subprocess.run", fake)

    mod = _load_entrypoint()
    rc = mod.main()
    assert rc == 0

    # Look for the POST that creates the review comment.
    posted = [
        c for c in fake.calls
        if "pulls/42/comments" in " ".join(c)
        and "POST" in c
    ]
    assert posted, (
        f"expected a POST to pulls/42/comments; saw: {fake.calls}"
    )
    body_arg = next(
        a for a in posted[0]
        if isinstance(a, str) and a.startswith("body=")
    )
    assert "GHA-001" in body_arg
    assert "<!-- pipeline-check-id:" in body_arg


def test_finding_outside_diff_lands_in_summary(monkeypatch, env):
    findings = [
        {
            "check_id": "GHA-002", "title": "Bad trigger",
            "severity": "HIGH", "passed": False,
            "description": "pull_request_target", "recommendation": "fix",
            "resource": ".github/workflows/release.yml",
            "locations": [
                {"path": ".github/workflows/release.yml",
                 "start_line": 99, "end_line": 99},
            ],
        },
    ]
    # Diff only touches lines 10..12 — the finding sits at line 99.
    fake = FakeProcess([
        ("pipeline_check", _scanner_response(findings)),
        ("repos/acme/repo/pulls/42/files",
         (0, _gh_pr_files_response(
             (".github/workflows/release.yml",
              "@@ -10,2 +10,3 @@\n line\n+added\n line\n"),
         ), "")),
        ("repos/acme/repo/pulls/42/comments", (0, "[]", "")),
        ("repos/acme/repo/issues/42/comments", (0, "[]", "")),
    ])
    monkeypatch.setattr("subprocess.run", fake)

    _load_entrypoint().main()

    # No review comment posted.
    review_posts = [
        c for c in fake.calls
        if "pulls/42/comments" in " ".join(c) and "POST" in c
    ]
    assert not review_posts
    # Summary issue-comment posted.
    summary_posts = [
        c for c in fake.calls
        if "issues/42/comments" in " ".join(c) and "POST" in c
    ]
    assert summary_posts, fake.calls
    body = next(
        a for a in summary_posts[0]
        if isinstance(a, str) and a.startswith("body=")
    )
    assert "GHA-002" in body
    assert "outside the PR diff" in body


def test_existing_marker_is_patched_not_duplicated(monkeypatch, env):
    """Re-running with a finding that already has a bot comment
    causes a PATCH, not a second POST."""
    import hashlib
    check_id = "GHA-001"
    path = ".github/workflows/release.yml"
    line = 11
    digest = hashlib.sha1(
        f"{path}:{line}:{check_id}".encode(),
    ).hexdigest()[:16]
    marker = f"{check_id}:{digest}"

    findings = [
        {
            "check_id": check_id, "title": "Pin actions",
            "severity": "HIGH", "passed": False,
            "description": "new description",
            "recommendation": "new fix",
            "resource": path,
            "locations": [
                {"path": path, "start_line": line, "end_line": line},
            ],
        },
    ]
    existing = json.dumps([{
        "id": 555,
        "body": (
            "**GHA-001** (HIGH) — Pin actions\n\nold description\n\n"
            f"**Fix:** old fix\n\n<!-- pipeline-check-id: {marker} -->"
        ),
    }])
    fake = FakeProcess([
        ("pipeline_check", _scanner_response(findings)),
        ("repos/acme/repo/pulls/42/files",
         (0, _gh_pr_files_response(
             (path, "@@ -10,3 +10,5 @@\n line\n+u\n+v\n line\n"),
         ), "")),
        ("repos/acme/repo/pulls/42/comments", (0, existing, "")),
        ("repos/acme/repo/issues/42/comments", (0, "[]", "")),
    ])
    monkeypatch.setattr("subprocess.run", fake)

    _load_entrypoint().main()

    # PATCH on the existing comment id 555.
    patches = [
        c for c in fake.calls
        if "PATCH" in c and "pulls/comments/555" in " ".join(c)
    ]
    assert patches, fake.calls
    posts = [
        c for c in fake.calls
        if "POST" in c and " pulls/42/comments" in (" " + " ".join(c) + " ")
    ]
    assert not posts, "should patch, not post a second comment"


def test_missing_locations_routes_to_summary(monkeypatch, env):
    findings = [
        {
            "check_id": "AWS-IAM-001", "title": "loose IAM",
            "severity": "HIGH", "passed": False,
            "description": "wildcard policy", "recommendation": "tighten",
            "resource": "arn:aws:iam::1234567890:role/Foo",
            # locations omitted entirely — common for AWS scans.
        },
    ]
    fake = FakeProcess([
        ("pipeline_check", _scanner_response(findings)),
        ("repos/acme/repo/pulls/42/files", (0, "[]", "")),
        ("repos/acme/repo/pulls/42/comments", (0, "[]", "")),
        ("repos/acme/repo/issues/42/comments", (0, "[]", "")),
    ])
    monkeypatch.setattr("subprocess.run", fake)

    _load_entrypoint().main()

    review_posts = [
        c for c in fake.calls
        if "POST" in c and " pulls/42/comments" in (" " + " ".join(c) + " ")
    ]
    assert not review_posts
    summary_posts = [
        c for c in fake.calls
        if "issues/42/comments" in " ".join(c) and "POST" in c
    ]
    assert summary_posts


def test_read_only_token_falls_back_to_step_summary(monkeypatch, env):
    """When every gh api call fails, content still lands in
    $GITHUB_STEP_SUMMARY so the job page shows what happened."""
    findings = [
        {
            "check_id": "GHA-001", "title": "Pin actions",
            "severity": "HIGH", "passed": False,
            "description": "demo", "recommendation": "demo",
            "resource": ".github/workflows/release.yml",
            "locations": [
                {"path": ".github/workflows/release.yml",
                 "start_line": 5, "end_line": 5},
            ],
        },
    ]
    fake = FakeProcess([
        ("pipeline_check", _scanner_response(findings)),
        # Every gh api call returns nonzero with check=True → raises.
        ("gh", (1, "", "403 Forbidden")),
    ])
    monkeypatch.setattr("subprocess.run", fake)

    _load_entrypoint().main()

    # Step summary file was written.
    body = env.summary_file.read_text(encoding="utf-8")
    assert "pipeline-check" in body
    assert "GHA-001" in body
