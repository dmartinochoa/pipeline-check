"""Entrypoint for the pipeline-check PR-review action.

Reads ``PIPELINE_CHECK_*`` env vars set by ``action.yml``, runs
``pipeline_check`` with JSON output, maps each finding's line to the
matching PR diff hunk, and posts:

  - one review comment per finding whose ``(path, line)`` lands inside
    a touched hunk (or every finding when ``COMMENT_MODE=summary``);
  - a single PR-level summary comment for everything else (or when the
    runner token isn't allowed to post review comments).

Idempotency: each comment body ends with a hidden marker
(``<!-- pipeline-check-id: <check_id>:<sha1(path:line:check_id)> -->``)
the script uses on subsequent runs to update or delete prior bot
comments instead of duplicating. The summary comment uses a single
fixed marker so it's upserted, not duplicated.

The script never raises on ``gh api`` failure — it falls back to
writing a job-summary section via ``$GITHUB_STEP_SUMMARY`` so the
finding list is always visible somewhere even when the API path
breaks (fork PRs with read-only token, rate limits, transient 5xx).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from typing import Any

# ── Configuration from env ───────────────────────────────────────────


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


PIPELINE = _env("PIPELINE_CHECK_PIPELINE", "auto")
SCAN_PATH = _env("PIPELINE_CHECK_PATH", ".")
SEVERITY = _env("PIPELINE_CHECK_SEVERITY", "MEDIUM").upper()
RESOLVE_REMOTE = _env("PIPELINE_CHECK_RESOLVE_REMOTE", "false").lower() == "true"
COMMENT_MODE = _env("PIPELINE_CHECK_COMMENT_MODE", "per-finding")
REPO = _env("GITHUB_REPOSITORY")
PR_NUMBER = _env("GITHUB_PR_NUMBER")
HEAD_SHA = _env("GITHUB_HEAD_SHA")

SUMMARY_MARKER = "<!-- pipeline-check-summary -->"
COMMENT_MARKER_RE = re.compile(
    r"<!-- pipeline-check-id: ([^>]+) -->"
)


# ── Scanner driver ───────────────────────────────────────────────────


def _build_scan_argv() -> list[str]:
    """Build the ``pipeline_check`` command for this run."""
    argv = ["pipeline_check", "--pipeline", PIPELINE, "-o", "json"]
    # ``--<provider>-path PATH`` mapping. ``auto`` falls through to
    # the scanner's own auto-detect.
    flag = {
        "github": "--gha-path",
        "gitlab": "--gitlab-path",
        "bitbucket": "--bitbucket-path",
        "azure": "--azure-path",
        "jenkins": "--jenkinsfile-path",
        "circleci": "--circleci-path",
        "cloudbuild": "--cloudbuild-path",
        "buildkite": "--buildkite-path",
        "tekton": "--tekton-path",
        "argo": "--argo-path",
        "dockerfile": "--dockerfile-path",
        "kubernetes": "--k8s-path",
        "helm": "--helm-path",
        "cloudformation": "--cfn-template",
        "terraform": "--tf-plan",
    }.get(PIPELINE)
    if flag:
        argv.extend([flag, SCAN_PATH])
    if SEVERITY:
        argv.extend(["--severity-threshold", SEVERITY])
    if RESOLVE_REMOTE:
        argv.append("--resolve-remote")
    return argv


def _run_scanner() -> dict[str, Any]:
    # If a pre-built JSON report was passed (e.g. from the top-level
    # action's stats sidecar), read it directly instead of re-scanning.
    report_path = _env("PIPELINE_CHECK_REPORT")
    if report_path and os.path.isfile(report_path):
        print(
            f"[pipeline-check-pr] reading pre-built report: {report_path}",
            file=sys.stderr,
        )
        try:
            with open(report_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"[pipeline-check-pr] could not read {report_path}: {exc}; "
                f"falling back to live scan.",
                file=sys.stderr,
            )

    argv = _build_scan_argv()
    print(f"[pipeline-check-pr] running: {' '.join(argv)}", file=sys.stderr)
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as exc:
        _fail(f"pipeline_check not on PATH: {exc}")
        raise SystemExit(1) from exc
    if not result.stdout.strip():
        _fail(
            f"pipeline_check produced no JSON output. "
            f"stderr:\n{result.stderr[-2000:]}"
        )
        raise SystemExit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _fail(f"pipeline_check output wasn't JSON: {exc}")
        raise SystemExit(1) from exc


# ── PR diff plumbing ─────────────────────────────────────────────────


_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _touched_lines(repo: str, pr_number: str) -> set[tuple[str, int]]:
    """Return ``{(path, line), ...}`` of every line the PR added/modified.

    Calls ``gh api``; an empty set on failure makes the script
    degrade to summary-only output.
    """
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/pulls/{pr_number}/files",
             "--paginate"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(
            f"[pipeline-check-pr] could not list PR files ({exc}); "
            f"falling back to PR-level summary.",
            file=sys.stderr,
        )
        return set()
    files = json.loads(out.stdout) if out.stdout.strip() else []
    touched: set[tuple[str, int]] = set()
    for f in files:
        patch = f.get("patch") or ""
        path = f.get("filename") or ""
        if not patch or not path:
            continue
        cursor = 0
        for line in patch.splitlines():
            m = _HUNK_HEADER_RE.match(line)
            if m:
                cursor = int(m.group(1))
                continue
            if line.startswith("+") and not line.startswith("+++"):
                touched.add((path, cursor))
                cursor += 1
            elif not line.startswith("-"):
                cursor += 1
    return touched


# ── Comment posting ──────────────────────────────────────────────────


def _marker_id(check_id: str, path: str, line: int) -> str:
    """Stable marker identifying one bot comment."""
    digest = hashlib.sha1(
        f"{path}:{line}:{check_id}".encode(),
    ).hexdigest()[:16]
    return f"{check_id}:{digest}"


def _existing_review_comments(
    repo: str, pr_number: str,
) -> list[dict[str, Any]]:
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/pulls/{pr_number}/comments",
             "--paginate"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    return json.loads(out.stdout) if out.stdout.strip() else []


def _existing_issue_comments(
    repo: str, pr_number: str,
) -> list[dict[str, Any]]:
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/issues/{pr_number}/comments",
             "--paginate"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    return json.loads(out.stdout) if out.stdout.strip() else []


def _post_review_comment(
    repo: str, pr_number: str, path: str, line: int,
    body: str, commit_id: str,
) -> bool:
    try:
        subprocess.run(
            [
                "gh", "api", "--method", "POST",
                f"repos/{repo}/pulls/{pr_number}/comments",
                "-f", f"body={body}",
                "-f", f"commit_id={commit_id}",
                "-f", f"path={path}",
                "-F", f"line={line}",
                "-f", "side=RIGHT",
            ],
            capture_output=True, text=True, check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"[pipeline-check-pr] review comment failed: {exc}",
              file=sys.stderr)
        return False


def _patch_review_comment(
    repo: str, comment_id: int, body: str,
) -> bool:
    try:
        subprocess.run(
            [
                "gh", "api", "--method", "PATCH",
                f"repos/{repo}/pulls/comments/{comment_id}",
                "-f", f"body={body}",
            ],
            capture_output=True, text=True, check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _delete_review_comment(repo: str, comment_id: int) -> None:
    try:
        subprocess.run(
            ["gh", "api", "--method", "DELETE",
             f"repos/{repo}/pulls/comments/{comment_id}"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass


def _upsert_summary(repo: str, pr_number: str, body: str) -> None:
    """Post or update the single PR-level summary comment."""
    full_body = f"{body}\n\n{SUMMARY_MARKER}"
    existing = _existing_issue_comments(repo, pr_number)
    for comment in existing:
        if SUMMARY_MARKER in (comment.get("body") or ""):
            try:
                subprocess.run(
                    ["gh", "api", "--method", "PATCH",
                     f"repos/{repo}/issues/comments/{comment['id']}",
                     "-f", f"body={full_body}"],
                    capture_output=True, text=True, check=True,
                )
                return
            except (FileNotFoundError, subprocess.CalledProcessError):
                break
    try:
        subprocess.run(
            ["gh", "api", "--method", "POST",
             f"repos/{repo}/issues/{pr_number}/comments",
             "-f", f"body={full_body}"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(
            f"[pipeline-check-pr] summary post failed: {exc}; "
            f"falling back to job summary.",
            file=sys.stderr,
        )
        _write_step_summary(body)


# ── Reporting helpers ────────────────────────────────────────────────


def _format_review_body(finding: dict[str, Any], marker: str) -> str:
    sev = finding.get("severity", "?")
    title = finding.get("title", "")
    desc = finding.get("description", "")
    rec = finding.get("recommendation", "")
    return (
        f"**{finding['check_id']}** ({sev}) — {title}\n\n"
        f"{desc}\n\n"
        f"**Fix:** {rec}\n\n"
        f"<!-- pipeline-check-id: {marker} -->"
    )


def _format_summary(
    findings: list[dict[str, Any]], orphans: list[dict[str, Any]],
) -> str:
    failed = [f for f in findings if not f.get("passed", True)]
    lines = [
        "## pipeline-check",
        "",
        f"**{len(failed)} finding(s)** at "
        f"severity ≥ {SEVERITY}.",
        "",
    ]
    if orphans:
        lines.append("### Findings outside the PR diff")
        lines.append("")
        for f in orphans:
            loc = (f.get("locations") or [{}])[0]
            path = loc.get("path", f.get("resource", ""))
            line = loc.get("start_line")
            where = f"`{path}:{line}`" if line else f"`{path}`"
            lines.append(
                f"- **{f['check_id']}** ({f.get('severity')}) "
                f"{where} — {f.get('title', '')}"
            )
        lines.append("")
    return "\n".join(lines)


def _write_step_summary(body: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(body)
            fh.write("\n")
    except OSError as exc:
        print(f"[pipeline-check-pr] could not write step summary: {exc}",
              file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"[pipeline-check-pr] {msg}", file=sys.stderr)
    _write_step_summary(f"## pipeline-check\n\n{msg}\n")


# ── Main ────────────────────────────────────────────────────────────


def main() -> int:
    if not REPO or not PR_NUMBER or not HEAD_SHA:
        _fail(
            "missing GITHUB_REPOSITORY / GITHUB_PR_NUMBER / "
            "GITHUB_HEAD_SHA — this action only runs on a "
            "pull_request trigger."
        )
        return 0  # don't fail the job; just don't comment

    report = _run_scanner()
    findings = report.get("findings") or []
    failed = [f for f in findings if not f.get("passed", True)]
    print(
        f"::set-output name=findings-count::{len(findings)}",
    )  # legacy GHA syntax; harmless
    # Modern outputs
    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a", encoding="utf-8") as fh:
            fh.write(f"findings-count={len(findings)}\n")
            fh.write(f"failed-count={len(failed)}\n")

    if not failed:
        _upsert_summary(
            REPO, PR_NUMBER,
            "## pipeline-check\n\nNo findings at severity ≥ "
            f"{SEVERITY}.",
        )
        return 0

    touched = _touched_lines(REPO, PR_NUMBER)
    existing = _existing_review_comments(REPO, PR_NUMBER)
    existing_by_marker: dict[str, dict[str, Any]] = {}
    for c in existing:
        m = COMMENT_MARKER_RE.search(c.get("body") or "")
        if m:
            existing_by_marker[m.group(1)] = c

    seen_markers: set[str] = set()
    orphans: list[dict[str, Any]] = []
    for f in failed:
        locs = f.get("locations") or []
        if not locs and COMMENT_MODE == "per-finding":
            orphans.append(f)
            continue
        # Per-finding mode: try to comment on each precise location
        # that's actually in the diff. Locations not in the diff are
        # collected for the summary fallback.
        emitted = False
        for loc in locs:
            path = loc.get("path", "")
            line = loc.get("start_line")
            if not path or not line:
                continue
            # GitHub's API expects repo-relative paths. Normalize OS
            # path separators.
            path = path.replace("\\", "/")
            if (path, line) not in touched:
                continue
            if COMMENT_MODE != "per-finding":
                continue
            marker = _marker_id(f["check_id"], path, line)
            seen_markers.add(marker)
            body = _format_review_body(f, marker)
            prior = existing_by_marker.get(marker)
            if prior is not None:
                if (prior.get("body") or "") != body:
                    _patch_review_comment(REPO, prior["id"], body)
                emitted = True
            else:
                if _post_review_comment(
                    REPO, PR_NUMBER, path, line, body, HEAD_SHA,
                ):
                    emitted = True
        if not emitted:
            orphans.append(f)

    # Tidy: delete prior bot comments whose findings have disappeared.
    for marker, comment in existing_by_marker.items():
        if marker in seen_markers:
            continue
        _delete_review_comment(REPO, comment["id"])

    # Summary covers orphans (findings without a precise location, or
    # whose location wasn't part of this PR's diff) plus the headline.
    _upsert_summary(REPO, PR_NUMBER, _format_summary(failed, orphans))

    # Always write to step summary too — provides a job-summary
    # backstop for fork PRs with read-only token.
    _write_step_summary(_format_summary(failed, orphans))
    return 0


if __name__ == "__main__":
    sys.exit(main())
