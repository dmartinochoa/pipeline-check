"""End-to-end CLI integration tests for ``--policy`` and ``--list-policies``.

Unit tests in ``test_policies.py`` cover the parser contract. This
module verifies the CLI flag wiring: discoverability, that policy
values become click defaults, that explicit flags still override
them, and the ``--list-policies`` exit behavior.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from click.testing import CliRunner

from pipeline_check.cli import scan


def _minimal_gha_repo(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # Workflow contains an unpinned third-party action so GHA-001
    # fires reliably. That gives us a real failing finding to gate on.
    (wf_dir / "ci.yml").write_text(textwrap.dedent("""
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: echo hi
    """).strip() + "\n")
    return tmp_path


def _write_policy(tmp_path: Path, name: str, body: str) -> None:
    pol_dir = tmp_path / "policies"
    pol_dir.mkdir(exist_ok=True)
    (pol_dir / f"{name}.yml").write_text(body, encoding="utf-8")


class TestListPolicies:
    def test_list_policies_prints_name_and_source(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write_policy(
            tmp_path, "pre-merge",
            "description: PR gate\ngate:\n  fail_on: HIGH\n",
        )
        _write_policy(
            tmp_path, "release",
            "description: release-only\ngate:\n  fail_on: MEDIUM\n",
        )
        runner = CliRunner()
        result = runner.invoke(scan, ["--list-policies"])
        assert result.exit_code == 0, result.output
        assert "pre-merge" in result.output
        assert "release" in result.output
        assert "PR gate" in result.output

    def test_list_policies_lists_builtins_when_no_local(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """With no local policies, the built-in packs are still listed."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(scan, ["--list-policies"])
        assert result.exit_code == 0, result.output
        assert "slsa-l3" in result.output
        assert "pci-dss" in result.output
        assert "<built-in" in result.output

    def test_list_policies_local_shadows_builtin(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """A local policy named like a built-in is listed once, from disk."""
        monkeypatch.chdir(tmp_path)
        _write_policy(
            tmp_path, "slsa-l3",
            "description: my custom slsa gate\ngate:\n  fail_on: LOW\n",
        )
        runner = CliRunner()
        result = runner.invoke(scan, ["--list-policies"])
        assert result.exit_code == 0, result.output
        # The local file's description wins; the built-in line is gone.
        assert "my custom slsa gate" in result.output
        assert "SLSA Build L3 focus" not in result.output


class TestPolicyResolution:
    def test_unknown_policy_emits_usage_error(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(scan, ["--policy", "ghost"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_policy_load_announces_to_stderr(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "pre-merge",
            "description: PR gate\ngate:\n  fail_on: CRITICAL\n",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "pre-merge",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        # Click 8.2+ merges stderr into ``result.output``; we just
        # confirm the load message landed in the combined stream.
        assert "[policy] loaded 'pre-merge'" in result.output

    def test_builtin_pack_resolves_without_local_file(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """``--policy slsa-l3`` resolves the built-in pack with no local file."""
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "slsa-l3",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        assert "[policy] loaded 'slsa-l3'" in result.output


class TestPolicyGateApplication:
    def test_policy_fail_on_blocks_high(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Policy ``fail_on: HIGH`` should fail the gate on a HIGH GHA-001."""
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "pr-strict",
            "gate:\n  fail_on: HIGH\n",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "pr-strict",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        # GHA-001 fires on `actions/checkout@v4` (unpinned tag) as HIGH;
        # fail_on=HIGH must trip the gate.
        assert result.exit_code == 1, result.output

    def test_cli_flag_overrides_policy(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """An explicit ``--fail-on CRITICAL`` overrides the policy's HIGH."""
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "pr-strict",
            "gate:\n  fail_on: HIGH\n",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "pr-strict",
                "--fail-on", "CRITICAL",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        # GHA-001 alone is HIGH not CRITICAL; CLI override should let
        # the gate pass.
        assert result.exit_code == 0, result.output


class TestPolicyChecksFilter:
    def test_policy_checks_whitelist_applied(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "only-gha-001",
            "checks: [GHA-001]\n",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "only-gha-001",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        doc = json.loads(result.stdout)
        # Every reported finding should be GHA-001 (the only check the
        # policy whitelisted).
        for finding in doc["findings"]:
            assert finding["check_id"] == "GHA-001", finding


class TestPolicyOverrides:
    def test_policy_severity_override_applied(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """Policy override demotes GHA-001 from HIGH to LOW, gate passes.

        Combines ``checks:`` (so only GHA-001 is in scope) with
        ``overrides:`` to demote it; that gives us a single-finding
        scenario to verify both layers wire through cleanly.
        """
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "demote",
            "checks: [GHA-001]\n"
            "gate:\n"
            "  fail_on: HIGH\n"
            "overrides:\n"
            "  GHA-001:\n"
            "    severity: LOW\n",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "demote",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        # Override demoted to LOW, gate fail_on=HIGH no longer triggers.
        assert result.exit_code == 0, result.output
        doc = json.loads(result.stdout)
        gha001 = [
            f for f in doc["findings"]
            if f["check_id"] == "GHA-001" and not f["passed"]
        ]
        assert gha001, "expected at least one failing GHA-001"
        # Every failing GHA-001 should carry the demoted severity.
        for f in gha001:
            assert f["severity"] == "LOW", f


class TestPolicyConfigPrecedence:
    def test_config_file_overrides_policy(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        """``.pipeline-check.yml`` should override matching policy keys."""
        monkeypatch.chdir(tmp_path)
        repo = _minimal_gha_repo(tmp_path)
        _write_policy(
            tmp_path, "loose",
            "gate:\n  fail_on: CRITICAL\n",
        )
        # Config file tightens to HIGH; that should override the policy.
        (tmp_path / ".pipeline-check.yml").write_text(
            "gate:\n  fail_on: HIGH\n", encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(
            scan,
            [
                "--policy", "loose",
                "--pipeline", "github",
                "--gha-path", str(repo / ".github" / "workflows"),
                "--output", "json",
                "--no-chains",
            ],
        )
        # Config's HIGH wins over policy's CRITICAL; GHA-001 HIGH trips.
        assert result.exit_code == 1, result.output
