"""Operational subcommands dispatched by ``cli.main``: init / fleet / fix-pr.

Extracted from ``cli.py``. Unlike the cli_aux_commands verbs, these carry a
little scanner-setup state (the ``_INIT_*`` maps, ``_init_scanner_kwargs_for``,
``_print_init_summary``, ``_fix_pr_scan``), which moves here with them. ``init``
and ``fix-pr`` construct a Scanner directly, so ``Scanner`` / ``MultiScanner``
are module-level names here, the smart-init tests patch
``pipeline_check.cli_ops_commands.Scanner``. ``cli`` re-imports the three command
objects so ``main``'s dispatch and the ``pipeline_check.cli.<cmd>`` test imports
keep working.
"""
from __future__ import annotations

import os
from typing import Any

import click

from . import __version__
from .cli_completion import _complete_check_ids
from .core import autofix as _autofix
from .core.detect import (
    detect_all_pipelines_from_cwd as _detect_all_pipelines_from_cwd,
)
from .core.detect import (
    detect_pipeline_from_cwd as _detect_pipeline_from_cwd,
)
from .core.fix_apply import (
    plan_fix_edits as _plan_fix_edits,
)
from .core.fix_apply import (
    write_fix_edits as _write_fix_edits,
)
from .core.scanner import MultiScanner, Scanner

# ────────────────────────────────────────────────────────────────────────────
# `init` subcommand, scaffold a starter config file.
# ────────────────────────────────────────────────────────────────────────────


#: Cwd-relative paths each provider needs to find its target files when
#: ``init`` constructs a Scanner with no flags. Keys must match the
#: names returned by :func:`_detect_pipeline_from_cwd`. Each value is a
#: tuple of ``(scanner_kwarg, candidate_paths)``; init picks the first
#: candidate that exists. Providers that need credentials or a remote
#: target the scaffold can't guess (AWS, oci, scm) are listed in
#: :data:`_INIT_SKIP_PROVIDERS` instead and bypass the scan entirely.
_INIT_SCANNER_KWARGS: dict[str, tuple[str, tuple[str, ...]]] = {
    "github": ("gha_path", (".github/workflows",)),
    "gitea": ("gitea_path", (".gitea/workflows", ".forgejo/workflows")),
    "gitlab": ("gitlab_path", (".gitlab-ci.yml",)),
    "bitbucket": ("bitbucket_path", ("bitbucket-pipelines.yml",)),
    "azure": ("azure_path", ("azure-pipelines.yml",)),
    "jenkins": ("jenkinsfile_path", ("Jenkinsfile",)),
    "circleci": ("circleci_path", (".circleci/config.yml",)),
    "cloudbuild": ("cloudbuild_path", ("cloudbuild.yaml", "cloudbuild.yml")),
    "buildkite": (
        "buildkite_path",
        (".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"),
    ),
    "drone": ("drone_path", (".drone.yml", ".drone.yaml")),
    "harness": ("harness_path", (".harness",)),
    "dockerfile": ("dockerfile_path", ("Dockerfile", "Containerfile")),
    "modelfile": ("modelfile_path", ("Modelfile",)),
    "kubernetes": ("k8s_path", ("kubernetes", "k8s", "manifests")),
    "helm": ("helm_path", (".",)),
    "devenv": ("devenv_path", (".",)),
    "npm": ("npm_path", (".",)),
    "pypi": ("pypi_path", (".",)),
    "maven": ("maven_path", ("pom.xml",)),
    "cloudformation": (
        "cfn_template",
        (
            "template.yml", "template.yaml", "template.json",
            "cloudformation.yml", "cloudformation.yaml",
            "cfn.yml", "cfn.yaml",
        ),
    ),
}

#: Providers that smart-init can detect but not scan unattended (live
#: cloud credentials, registry pulls, GitHub admin tokens). For these,
#: the CLI writes a static scaffold and skips the scan instead of
#: surfacing a confusing "scan failed" exception in stderr.
_INIT_SKIP_PROVIDERS: frozenset[str] = frozenset({"aws", "azure_cloud", "gcp", "oci", "scm"})


def _init_scanner_kwargs_for(detected: str) -> dict[str, Any]:
    """Return Scanner constructor kwargs for the smart-init flow.

    Returns ``{}`` when the provider doesn't need a path. Callers
    should still try to construct the Scanner; if it fails, the caller
    falls back to writing a static scaffold.

    Return type is ``dict[str, Any]`` because the Scanner constructor
    type-checks each kwarg against its named parameter (a path string
    is fine for ``gha_path``, but mypy reads ``dict[str, str]`` as
    "every kwarg is ``str``" and trips on the unrelated keyword
    parameters that share its dict signature).
    """
    entry = _INIT_SCANNER_KWARGS.get(detected)
    if entry is None:
        return {}
    kwarg, candidates = entry
    for candidate in candidates:
        if os.path.exists(candidate):
            return {kwarg: candidate}
    return {}


@click.command(name="init")
@click.option(
    "--path",
    "target_path",
    default=".pipeline-check.yml",
    show_default=True,
    metavar="PATH",
    help="Write the scaffold to this path.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the target file if it already exists.",
)
@click.option(
    "--no-scan",
    "no_scan",
    is_flag=True,
    default=False,
    help=(
        "Skip the one-shot scan and write a static scaffold instead. Use "
        "when you want the bare template with no recommended gate / "
        "baseline."
    ),
)
@click.option(
    "--baseline-path",
    "baseline_path",
    default=None,
    metavar="PATH",
    help=(
        "Where to write the baseline JSON. Defaults to "
        "``.pipeline-check-baseline.json``. Ignored with --no-scan."
    ),
)
def init_cmd(
    target_path: str,
    force: bool,
    no_scan: bool,
    baseline_path: str | None,
) -> None:
    """Initialize pipeline_check in this repo: scan, baseline, scaffold.

    By default ``init`` runs one scan against whatever pipeline files
    it auto-detects, writes a baseline JSON capturing the current
    failing findings, and emits ``.pipeline-check.yml`` with a
    recommended ``gate.fail_on`` plus a baseline pointer so future CI
    runs only block on *new* regressions. Prints a "top 5 to fix"
    summary to stderr so the operator has a starting point.

    With ``--no-scan`` it falls back to the legacy behavior: write a
    commented-out scaffold only. ``--force`` overwrites an existing
    config file; existing baselines are always overwritten.
    """
    from .core.init_scan import (
        DEFAULT_BASELINE_PATH,
        build_init_scan_result,
    )
    from .core.init_template import render as _render_template

    if os.path.exists(target_path) and not force:
        raise click.UsageError(
            f"{target_path} already exists. Re-run with --force to overwrite."
        )

    detected = _detect_pipeline_from_cwd()

    if no_scan or detected is None or detected in _INIT_SKIP_PROVIDERS:
        # Either the user opted out, there's nothing to scan, or the
        # detected provider needs credentials / a remote target that
        # smart-init can't guess (AWS account, OCI registry, SCM
        # token). Fall back to the static scaffold so ``init`` still
        # does something useful.
        try:
            with open(target_path, "w", encoding="utf-8") as fh:
                fh.write(_render_template(detected))
        except OSError as exc:
            raise click.UsageError(
                f"could not write {target_path}: {exc}"
            ) from exc
        if no_scan:
            suffix = (
                f" (pipeline: {detected})"
                if detected
                else " (no CI files detected, edit the 'pipeline:' line "
                "before use)"
            )
        elif detected in _INIT_SKIP_PROVIDERS:
            suffix = (
                f" (pipeline: {detected}; this provider needs "
                f"credentials, smart-init skipped the scan. Run "
                f"`pipeline_check --pipeline {detected}` to scan once "
                f"those are set.)"
            )
        else:
            suffix = (
                " (no CI files detected; edit 'pipeline:' or rerun "
                "after adding one)"
            )
        click.echo(f"[init] wrote {target_path}{suffix}")
        return

    # Smart path: run a scan, write baseline + tuned config. Re-use
    # the module-level Scanner import so tests can patch
    # ``pipeline_check.cli.Scanner`` and have init see the mock.
    from .core.autofix import available_fixers

    bpath = baseline_path or DEFAULT_BASELINE_PATH

    click.echo(f"[init] scanning {detected!r} to tune the gate...", err=True)
    scanner_kwargs = _init_scanner_kwargs_for(detected)
    try:
        scanner = Scanner(pipeline=detected, **scanner_kwargs)
        findings = scanner.run()
    except Exception as exc:
        click.echo(
            f"[init] scan failed ({exc}); writing a static scaffold instead. "
            f"Rerun with --no-scan to skip the scan permanently.",
            err=True,
        )
        try:
            with open(target_path, "w", encoding="utf-8") as fh:
                fh.write(_render_template(detected))
        except OSError as inner:
            raise click.UsageError(
                f"could not write {target_path}: {inner}"
            ) from inner
        click.echo(f"[init] wrote {target_path} (pipeline: {detected})")
        return

    result = build_init_scan_result(
        findings,
        detected_pipeline=detected,
        tool_version=__version__,
        fixers=set(available_fixers()),
        baseline_path=bpath,
    )

    try:
        with open(target_path, "w", encoding="utf-8") as fh:
            fh.write(result.config_yaml)
    except OSError as exc:
        raise click.UsageError(
            f"could not write {target_path}: {exc}"
        ) from exc

    if result.has_failures:
        try:
            with open(bpath, "w", encoding="utf-8") as fh:
                fh.write(result.baseline_json)
        except OSError as exc:
            click.echo(
                f"[init] could not write baseline {bpath}: {exc}. Config "
                f"file is still written; remove the 'baseline:' line or "
                f"fix the path before running CI.",
                err=True,
            )

    _print_init_summary(result, target_path)


def _print_init_summary(result: Any, config_path: str) -> None:
    """Render the post-scan summary as a short guided tour to stderr.

    Rich gives the grade and severities the same color language as a
    scan report, so ``init`` and a normal run read as one product. The
    console writes to stderr (stdout stays clean for piping) and, under
    a non-terminal (tests, CI logs), renders as plain text, so the
    ``[init]`` log lines downstream tooling greps for survive intact.
    The literal ``[init]`` prefix is escaped (``\\[init]``) so Rich
    doesn't try to parse it as a ``[style]`` tag.
    """
    from rich.console import Console
    from rich.markup import escape as _esc

    from .core.reporter import _GRADE_STYLE, _SEVERITY_STYLE

    console = Console(stderr=True)

    # 1. What got written.
    console.print(
        rf"\[init] wrote [bold]{_esc(config_path)}[/bold] "
        f"(pipeline: {result.detected_pipeline})"
    )
    if result.has_failures:
        console.print(
            rf"\[init] wrote [bold]{_esc(result.baseline_path)}[/bold] "
            f"({result.failing_findings} failing finding(s) baselined)"
        )

    # 2. The result, in the scan report's color language.
    grade_style = _GRADE_STYLE.get(result.grade, "white")
    fail_on = result.recommended_fail_on.value
    console.print(
        f"\n  [{grade_style}]Grade {result.grade}[/{grade_style}] "
        f"[dim]·[/dim] score {result.score}/100"
    )
    if result.has_failures:
        console.print(
            f"  Gate set to [bold]fail_on={fail_on}[/bold]. Today's "
            f"{result.failing_findings} finding(s) are baselined, so CI "
            f"blocks only on [bold]new[/bold] ones."
        )
    else:
        console.print(
            f"  No failing findings. Gate set to [bold]fail_on={fail_on}[/bold] "
            f"from a clean slate (nothing to baseline)."
        )

    # 3. The shortlist, severity-colored, with forward-slashed paths.
    if result.top:
        console.print("\n" + r"\[init] top to fix first:")
        id_w = max(len(t.check_id) for t in result.top)
        for t in result.top:
            sev_style = _SEVERITY_STYLE.get(t.severity, "white")
            tag = "  [dim](autofix)[/dim]" if t.fixable else ""
            resource = _esc(t.resource.replace("\\", "/"))
            console.print(
                f"    [bold]{t.check_id:<{id_w}}[/bold]  "
                f"[{sev_style}]{t.severity.value:<8}[/{sev_style}]  "
                f"{_esc(t.title)}  [dim]{resource}[/dim]{tag}"
            )

    # 4. The guided "now what". Commit the artifacts; fix-oriented steps
    # only when there's something to fix.
    commit = f"commit [bold]{_esc(config_path)}[/bold]"
    if result.has_failures:
        commit += f" and [bold]{_esc(result.baseline_path)}[/bold]"
    console.print("\n" + r"\[init] next steps:")
    console.print(f"    [dim]1.[/dim] {commit}")
    if result.top:
        top_id = result.top[0].check_id
        console.print(
            "    [dim]2.[/dim] see every finding   [bold]pipeline_check[/bold]"
        )
        console.print(
            f"    [dim]3.[/dim] understand a rule   "
            f"[bold]pipeline_check explain {top_id}[/bold]"
        )
        console.print(
            "    [dim]4.[/dim] apply autofixes     "
            "[bold]pipeline_check --fix --apply[/bold]"
        )
    else:
        console.print(
            "    [dim]2.[/dim] wire it into CI     "
            f"[bold]pipeline_check --fail-on {fail_on}[/bold]"
        )


# ────────────────────────────────────────────────────────────────────────────
# `fleet` subcommand, scan a list of repos and emit a unified digest.
# ────────────────────────────────────────────────────────────────────────────


@click.command(name="fleet")
@click.option(
    "--repos",
    "repos_path",
    default=None,
    metavar="PATH",
    help=(
        "YAML file with repo coordinates. Entries can be bare "
        "'owner/repo' (GitHub), prefixed 'gitlab:group/project', "
        "or mappings with 'coord' + 'platform' keys."
    ),
)
@click.option(
    "--from-org",
    "from_org",
    default=None,
    metavar="ORG",
    help=(
        "Enumerate repos from an org/group/workspace via the SCM "
        "API. Requires a platform token in the environment "
        "(GITHUB_TOKEN, GITLAB_TOKEN, or BITBUCKET_TOKEN). "
        "Mutually exclusive with --repos."
    ),
)
@click.option(
    "--platform",
    "platform",
    default="github",
    show_default=True,
    type=click.Choice(["github", "gitlab", "bitbucket"]),
    help="SCM platform for --from-org enumeration.",
)
@click.option(
    "--include",
    "include_patterns",
    multiple=True,
    metavar="GLOB",
    help=(
        "Include only repos whose name matches this glob "
        "(repeatable, fnmatch syntax). Applied after repo discovery."
    ),
)
@click.option(
    "--exclude",
    "exclude_patterns",
    multiple=True,
    metavar="GLOB",
    help=(
        "Exclude repos whose name matches this glob "
        "(repeatable, fnmatch syntax). Applied after repo discovery."
    ),
)
@click.option(
    "--output-dir",
    "output_dir",
    default="fleet-out",
    show_default=True,
    metavar="PATH",
    help=(
        "Directory for the unified digest tree. Per-repo findings "
        "land at <output-dir>/<platform>/<owner>/<repo>/findings.json; "
        "the aggregate is at <output-dir>/fleet.json + fleet.md."
    ),
)
@click.option(
    "--per-repo-timeout",
    "timeout_sec",
    default=600,
    show_default=True,
    type=click.IntRange(30, 3600),
    help=(
        "Maximum seconds to spend on any single repo (clone + scan "
        "combined). A repo that exceeds this surfaces as a "
        "warning in the digest and the run continues with the "
        "remaining repos."
    ),
)
@click.option(
    "--jobs",
    "jobs",
    default=None,
    type=click.IntRange(0, 32),
    metavar="N",
    help=(
        "Number of repos to scan in parallel. "
        "0 runs sequentially (useful for debugging). "
        "Omit to auto-detect based on CPU count and repo count."
    ),
)
@click.option(
    "--scan-flags",
    "scan_flags_str",
    default=None,
    metavar="FLAGS",
    help=(
        "Extra flags forwarded verbatim to each per-repo "
        "pipeline_check subprocess, e.g. "
        "'--standard owasp_cicd_top_10 --resolve-remote'. "
        "Quote the whole value as a single string."
    ),
)
def fleet_cmd(
    repos_path: str | None,
    from_org: str | None,
    platform: str,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    output_dir: str,
    timeout_sec: int,
    jobs: int | None,
    scan_flags_str: str | None,
) -> None:
    """Scan a list of repositories and emit a unified posture digest.

    Each coordinate is shallow-cloned to a tmpdir, scanned via a
    fresh ``pipeline_check`` subprocess, and the per-repo findings
    plus a fleet-wide digest land under ``--output-dir``. A single
    repo's clone / scan failure becomes a warning, not an abort.
    """
    import shlex
    from pathlib import Path

    from .core.fleet import (
        apply_filters,
        default_worker_count,
        enumerate_org_repos,
        load_repo_list,
        run_fleet,
    )

    if repos_path and from_org:
        raise click.UsageError(
            "--repos and --from-org are mutually exclusive."
        )
    if not repos_path and not from_org:
        raise click.UsageError(
            "Provide either --repos or --from-org."
        )
    if from_org:
        try:
            repos = enumerate_org_repos(from_org, platform)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    else:
        assert repos_path is not None
        try:
            repos = load_repo_list(repos_path)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    if include_patterns or exclude_patterns:
        repos = apply_filters(
            repos,
            include=list(include_patterns) or None,
            exclude=list(exclude_patterns) or None,
        )
    if not repos:
        source = repos_path if repos_path else f"--from-org {from_org}"
        raise click.UsageError(
            f"[fleet] {source} yielded no repo coordinates."
        )
    out_dir = Path(output_dir)
    try:
        scan_flags = shlex.split(scan_flags_str) if scan_flags_str else None
    except ValueError as exc:
        # Unbalanced quotes in --scan-flags shouldn't crash with a raw
        # traceback.
        raise click.UsageError(f"--scan-flags is not parseable: {exc}") from exc
    effective_jobs = jobs if jobs is not None else default_worker_count(len(repos))
    digest = run_fleet(
        repos, out_dir,
        timeout_sec=timeout_sec,
        jobs=effective_jobs,
        scan_flags=scan_flags,
    )
    ok = sum(1 for s in digest.snapshots if s.ok)
    click.echo(
        f"[fleet] scanned {len(digest.snapshots)} repo(s) "
        f"({ok} OK, {len(digest.snapshots) - ok} errored) -> "
        f"{out_dir}/fleet.md"
    )
    for w in digest.warnings:
        click.echo(f"  warn: {w}", err=True)


# ────────────────────────────────────────────────────────────────────────────
# `fix-pr` subcommand, scan, apply autofixes, and open a PR / MR.
# ────────────────────────────────────────────────────────────────────────────


#: Maps the user-facing ``--safety`` choice to the ``generate_fix`` tier.
#: ``safe`` runs only safe fixers; ``all`` runs both tiers; ``unsafe``
#: runs only the inference-dependent ones. Mirrors ``--list-fixers``'
#: vocabulary so the two read the same.
_FIX_PR_TIERS: dict[str, str] = {
    "safe": "safe",
    "unsafe": "unsafe-only",
    "all": "unsafe",
}


def _fix_pr_scan(
    checks: list[str] | None,
) -> tuple[list[Any], list[str]]:
    """Auto-detect pipelines at cwd and return ``(findings, pipelines)``.

    Reuses the same detection table and per-provider path resolution as
    ``init``, minus the providers that need live credentials (AWS, the
    cloud-posture packs, OCI, SCM), which can't be autofixed on disk.
    Chains are disabled: fix-pr only needs per-file findings, not
    cross-rule correlation. Returns an empty pipeline list when nothing
    scannable is present so the caller can exit cleanly.
    """
    detected = [
        p for p in _detect_all_pipelines_from_cwd()
        if p not in _INIT_SKIP_PROVIDERS
    ]
    if not detected:
        return [], []
    scanner_kwargs: dict[str, Any] = {}
    for provider in detected:
        scanner_kwargs.update(_init_scanner_kwargs_for(provider))
    scanner: Scanner | MultiScanner
    if len(detected) == 1:
        scanner = Scanner(
            pipeline=detected[0], chains_enabled=False, **scanner_kwargs,
        )
    else:
        scanner = MultiScanner(
            pipelines=detected, chains_enabled=False, **scanner_kwargs,
        )
    findings = scanner.run(checks=checks)
    return findings, detected


@click.command(name="fix-pr")
@click.option(
    "--safety",
    "safety",
    type=click.Choice(["safe", "unsafe", "all"], case_sensitive=False),
    default="safe",
    show_default=True,
    help=(
        "Which autofixers to apply. 'safe' (default) only semantically "
        "equivalent edits; 'unsafe' only the inference-dependent ones; "
        "'all' both tiers. Run `pipeline_check --list-fixers` to see "
        "which fixer is in which tier."
    ),
)
@click.option(
    "--base",
    "base",
    default=None,
    metavar="BRANCH",
    help=(
        "Branch the PR / MR targets and the autofix branch is cut from. "
        "Defaults to the current branch."
    ),
)
@click.option(
    "--branch",
    "branch_name",
    default="pipeline-check/autofix",
    show_default=True,
    metavar="NAME",
    help=(
        "Name for the autofix branch. A numeric suffix is appended if it "
        "already exists, so repeat runs never collide."
    ),
)
@click.option(
    "--remote",
    "remote",
    default="origin",
    show_default=True,
    metavar="NAME",
    help="Git remote to push the branch to.",
)
@click.option(
    "--checks",
    "-c",
    "checks",
    multiple=True,
    metavar="CHECK_ID",
    shell_complete=_complete_check_ids,
    help=(
        "Limit the fix to specific check ID(s). Repeat to include "
        "several. Omit to fix every finding with a matching fixer."
    ),
)
@click.option(
    "--title",
    "title",
    default=None,
    metavar="TEXT",
    help="PR / MR title. Defaults to a summary of the fixed rules.",
)
@click.option(
    "--body",
    "body",
    default=None,
    metavar="TEXT",
    help=(
        "PR body (GitHub). Defaults to a generated summary listing the "
        "remediated checks. GitLab MRs carry the title only."
    ),
)
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    default=False,
    help=(
        "Show the patch and the planned git actions without touching the "
        "repo. No branch, no commit, no push."
    ),
)
@click.option(
    "--push/--no-push",
    "do_push",
    default=True,
    show_default=True,
    help=(
        "Push the branch and open the request. --no-push stops after the "
        "local commit so you can review before sharing."
    ),
)
@click.option(
    "--allow-dirty",
    "allow_dirty",
    is_flag=True,
    default=False,
    help=(
        "Proceed even when the working tree has uncommitted changes. "
        "Only the autofix edits are staged, but the branch is still cut "
        "from the current (dirty) HEAD."
    ),
)
def fix_pr_cmd(
    safety: str,
    base: str | None,
    branch_name: str,
    remote: str,
    checks: tuple[str, ...],
    title: str | None,
    body: str | None,
    dry_run: bool,
    do_push: bool,
    allow_dirty: bool,
) -> None:
    """Scan, apply autofixes, and open a pull / merge request.

    Runs a scan over the auto-detected pipeline files, applies the
    autofixers of the chosen ``--safety`` tier, commits the changed
    files to a fresh branch, pushes, and opens the request. GitHub uses
    ``gh pr create``; GitLab creates the MR via push options (no token
    needed); other hosts get the branch pushed with manual instructions.

    Refuses to run on a dirty working tree by default so the commit
    never sweeps in unrelated edits (override with ``--allow-dirty``).
    Exits cleanly with no branch created when nothing is autofixable.
    """
    from .core import fix_pr as _fix_pr

    if _fix_pr.repo_root() is None:
        raise click.UsageError("fix-pr must run inside a git repository.")
    if not allow_dirty and _fix_pr.is_dirty():
        raise click.UsageError(
            "working tree has uncommitted changes. Commit or stash them "
            "first, or pass --allow-dirty to commit only the autofix edits."
        )

    base_branch = base or _fix_pr.current_branch()
    if base_branch in ("", "HEAD"):
        raise click.UsageError(
            "could not determine the base branch (detached HEAD?). Pass "
            "--base BRANCH explicitly."
        )

    tier = _FIX_PR_TIERS[safety.lower()]
    check_filter = list(checks) or None

    click.echo("[fix-pr] scanning for autofixable findings...", err=True)
    try:
        findings, pipelines = _fix_pr_scan(check_filter)
    except Exception as exc:
        raise click.UsageError(f"scan failed: {exc}") from exc
    if not pipelines:
        click.echo(
            "[fix-pr] no scannable pipeline files detected at cwd; "
            "nothing to do.",
            err=True,
        )
        return

    edits, newlines, fixed_ids = _plan_fix_edits(findings, tier=tier)
    if not edits:
        click.echo(
            f"[fix-pr] no {safety} autofixes apply to the current findings. "
            "Nothing to open a PR for.",
            err=True,
        )
        return

    fixed_id_list = sorted(fixed_ids)
    pr_title = title or _fix_pr.default_title(fixed_id_list)
    pr_body = body or _fix_pr.build_body(fixed_id_list, len(edits), safety)

    if dry_run:
        for path in sorted(edits):
            try:
                with open(path, encoding="utf-8") as fh:
                    before = fh.read().replace("\r\n", "\n")
            except (OSError, UnicodeDecodeError):
                continue
            click.echo(_autofix.render_patch(path, before, edits[path]), nl=False)
        click.echo(
            f"\n[fix-pr] dry run: would fix {len(edits)} file(s) "
            f"({', '.join(fixed_id_list)}), commit to branch "
            f"{branch_name!r}, and open a PR against {base_branch!r}. "
            "No changes made.",
            err=True,
        )
        return

    # Cut the branch from the current HEAD, then write the edits onto it
    # so the base branch is never touched.
    try:
        branch = _fix_pr.unique_branch_name(branch_name)
        _fix_pr.checkout_new_branch(branch)
    except _fix_pr.GitError as exc:
        raise click.UsageError(str(exc)) from exc

    written = _write_fix_edits(edits, newlines)
    if not written:
        # Every write failed; abandon the empty branch and return to base.
        try:
            _fix_pr.checkout(base_branch)
        except _fix_pr.GitError:
            pass
        raise click.UsageError(
            "could not write any autofix edits to disk; left on branch "
            f"{branch!r}."
        )

    try:
        _fix_pr.commit(written, pr_title, pr_body)
    except _fix_pr.GitError as exc:
        raise click.UsageError(f"commit failed: {exc}") from exc
    click.echo(
        f"[fix-pr] committed {len(written)} file(s) to branch {branch!r}.",
        err=True,
    )

    if not do_push:
        click.echo(
            f"[fix-pr] --no-push: branch {branch!r} is ready. Push it and "
            "open the request when you're satisfied with the diff.",
            err=True,
        )
        return

    platform = _fix_pr.detect_platform(_fix_pr.remote_url(remote))
    result = _fix_pr.FixPrResult(
        branch=branch, base=base_branch, platform=platform,
        file_count=len(written), check_ids=fixed_id_list,
    )

    try:
        if platform == _fix_pr.GITLAB:
            _fix_pr.push(
                remote, branch,
                push_options=_fix_pr.gitlab_push_options(base_branch, pr_title),
            )
            result.pushed = True
            result.note = (
                "GitLab MR created via push options. Open the branch URL "
                "git printed above to review it."
            )
        else:
            _fix_pr.push(remote, branch)
            result.pushed = True
            if platform == _fix_pr.GITHUB and _fix_pr.gh_available():
                result.pr_url = _fix_pr.gh_create_pr(
                    base_branch, branch, pr_title, pr_body,
                )
            elif platform == _fix_pr.GITHUB:
                result.note = (
                    "GitHub `gh` CLI not found. Branch pushed; open the PR "
                    "from the compare URL git printed, or install gh."
                )
            else:
                result.note = (
                    f"Host {platform!r} has no automated PR path. Branch "
                    "pushed; open the request in your host's UI."
                )
    except _fix_pr.GitError as exc:
        raise click.UsageError(
            f"push / PR step failed: {exc}. The commit is on local branch "
            f"{branch!r}; push it by hand once resolved."
        ) from exc

    if result.pr_url:
        click.echo(f"[fix-pr] opened {result.pr_url}")
    else:
        click.echo(
            f"[fix-pr] pushed branch {branch!r} -> {remote} "
            f"(base {base_branch!r}).",
            err=True,
        )
        if result.note:
            click.echo(f"[fix-pr] {result.note}", err=True)
