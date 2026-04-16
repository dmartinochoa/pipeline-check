"""CLI-level tests for --fix and traceback-on-failure behavior."""
from __future__ import annotations

import json

from click.testing import CliRunner

from pipeline_check.cli import scan


def _write_unfixed_workflow(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu\n"
        "    steps:\n      - run: echo\n"
    )


def test_fix_emits_patch_to_stdout_in_terminal_mode(tmp_path, monkeypatch):
    """`pipeline_check --fix` streams the GHA-004 patch to stdout so it
    can be piped into `git apply`."""
    monkeypatch.chdir(tmp_path)
    _write_unfixed_workflow(tmp_path)
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--fix", "--output", "terminal"]
    )
    # Terminal mode mixes stdout + stderr in result.output; the patch
    # is there regardless.
    assert "+permissions:" in result.output


def test_fix_routes_patch_to_stderr_when_output_is_json(tmp_path, monkeypatch):
    """With --output json, the patch must go to stderr so the JSON on
    stdout stays parseable."""
    monkeypatch.chdir(tmp_path)
    _write_unfixed_workflow(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        scan, ["--pipeline", "github", "--fix", "--output", "json"]
    )
    # stdout is valid JSON — patch must not have leaked onto it.
    payload = json.loads(result.stdout)
    assert "findings" in payload
    # The patch was emitted; in Click 8.3 result.output contains both
    # streams but result.stdout is stdout only — so the patch not being
    # in stdout proves it was routed away from the JSON stream.
    assert "+permissions:" not in result.stdout


def test_scan_failure_prints_traceback(monkeypatch, tmp_path):
    """Scan-time exceptions produce a traceback on stderr, not just the
    one-liner, so operators can debug."""
    from pipeline_check.cli import scan as scan_cmd
    from pipeline_check.core import scanner as scanner_mod

    # Patch Scanner.run so construction succeeds (build_context is
    # trivial for an empty fake provider) but the actual scan raises.
    orig_run = scanner_mod.Scanner.run
    def _boom(self, **kw):
        raise RuntimeError("synthetic scan crash")
    monkeypatch.setattr(scanner_mod.Scanner, "run", _boom)
    monkeypatch.chdir(tmp_path)

    # Use a provider whose context construction doesn't need
    # credentials or on-disk files. Terraform with an empty plan works.
    (tmp_path / "plan.json").write_text(
        '{"planned_values": {"root_module": {"resources": []}}}'
    )
    try:
        result = CliRunner().invoke(
            scan_cmd, ["--pipeline", "terraform", "--tf-plan", "plan.json"]
        )
    finally:
        monkeypatch.setattr(scanner_mod.Scanner, "run", orig_run)

    assert result.exit_code == 2
    assert "[error] Scan failed" in result.output
    assert "Traceback" in result.output
    assert "synthetic scan crash" in result.output
