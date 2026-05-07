"""End-to-end resolver test using the on-disk fetcher.

Stages a fake same-org repo on tmp disk, points ``--gha-search-path``
at it, and runs the full Scanner. No network involved. Verifies:

  - the resolver-fetched callee body is scanned
  - findings on the callee carry the synthetic
    ``<caller> -> <owner>/<repo>/...@<ref>`` resource string
  - GHA-019 picks up a token-persistence pattern *inside* the callee
"""
from __future__ import annotations

from pathlib import Path

from pipeline_check.core.scanner import Scanner

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _stage_same_org_layout(root: Path) -> Path:
    """Create ``<root>/myorg/shared/.github/workflows/release.yml``.

    The callee body fails GHA-019 (token persistence) so we can
    assert the rule fired *on the resolved body* by checking the
    finding's resource string for the synthetic chain.
    """
    callee_dir = root / "myorg" / "shared" / ".github" / "workflows"
    callee_dir.mkdir(parents=True)
    (callee_dir / "release.yml").write_text(
        "on: workflow_call\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.GITHUB_TOKEN }} >> creds.txt\n",
        encoding="utf-8",
    )
    return root


def _stage_caller(workflows_dir: Path) -> Path:
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "main.yml").write_text(
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  call:\n"
        f"    uses: myorg/shared/.github/workflows/release.yml@{_SHA}\n"
        "    secrets: inherit\n",
        encoding="utf-8",
    )
    return workflows_dir


def test_resolver_e2e_scans_callee_body(tmp_path):
    workflows_dir = tmp_path / "caller" / ".github" / "workflows"
    _stage_caller(workflows_dir)
    search_root = tmp_path / "siblings"
    _stage_same_org_layout(search_root)

    scanner = Scanner(
        pipeline="github",
        gha_path=str(workflows_dir),
        resolve_remote=True,
        gha_search_paths=[str(search_root)],
        no_cache=True,  # avoid clobbering the user's real cache
    )
    findings = scanner.run()
    # GHA-019 fires on the callee.
    gha019 = [f for f in findings if f.check_id == "GHA-019" and not f.passed]
    assert gha019, "GHA-019 did not fire — callee body was not scanned"
    # Resource string carries the resolution chain.
    chained = [f for f in gha019 if " -> " in f.resource]
    assert chained, (
        f"expected a synthetic chained resource string; got: "
        f"{[f.resource for f in gha019]}"
    )
    # The inherit-secrets note appears on the callee finding.
    assert any("secrets: inherit" in f.description for f in chained)


def test_resolver_off_by_default_emits_skip_warning(tmp_path):
    workflows_dir = tmp_path / "caller" / ".github" / "workflows"
    _stage_caller(workflows_dir)

    scanner = Scanner(
        pipeline="github",
        gha_path=str(workflows_dir),
        # resolve_remote omitted → False default
    )
    scanner.run()
    # Skip warning surfaced via context warnings.
    assert any(
        "rerun with --resolve-remote" in w
        for w in scanner.metadata.warnings
    ), scanner.metadata.warnings


# Note: the failure-path E2E test would hit the live HTTP fetcher
# and is therefore brittle in offline environments. Failure-mode
# coverage (network unreachable, 404, malformed YAML) lives in
# tests/github/test_resolver.py with the in-memory FakeFetcher.
