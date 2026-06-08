"""Tests for the ``verify-artifact`` provenance gate.

The engine (``pipeline_check.core.provenance``) is pure orchestration:
binary discovery and subprocess execution are both injected, so these
tests drive every verdict path without a real ``cosign`` /
``slsa-verifier`` / ``gh`` on PATH. The CLI tests stub the engine and
assert the exit-code contract and rendered output.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pipeline_check.cli import verify_artifact_cmd
from pipeline_check.core import provenance as prov
from pipeline_check.core.provenance import (
    ProvenanceError,
    ProvenanceReport,
    RunOutcome,
    ToolResult,
    Verdict,
    VerifyPolicy,
    default_runner,
    extract_builder,
    verify_artifact,
)

_SLSA_PASS = (
    'Verified signature against tlog entry index 1\n'
    'Verified build using builder '
    '"https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1.2.3"\n'
    'PASSED: SLSA verification passed'
)


def _all_present(name: str) -> str:
    """A ``which`` that reports every tool installed."""
    return f"/usr/local/bin/{name}"


def _none_present(_name: str) -> None:
    """A ``which`` that reports no tool installed."""
    return None


def _passing_runner(argv, timeout):  # type: ignore[no-untyped-def]
    if "verify-image" in argv or "verify-artifact" in argv:
        return RunOutcome(True, 0, _SLSA_PASS, "")
    return RunOutcome(True, 0, "Verified OK", "")


# ── verdict folding ───────────────────────────────────────────────────


def test_all_tools_pass_yields_pass() -> None:
    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        source_uri="github.com/acme/api",
        certificate_identity="https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1.2.3",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
        owner="acme",
    )
    report = verify_artifact(
        policy, runner=_passing_runner, which=_all_present,
    )
    assert report.verdict is Verdict.PASS
    assert report.exit_code == 0
    # builder surfaces from the slsa-verifier output.
    assert report.builder is not None
    assert ".github/workflows/release.yml@refs/tags/v1.2.3" in report.builder
    assert all(r.ran and r.ok for r in report.results)


def test_failing_tool_yields_fail_with_reason() -> None:
    def runner(argv, timeout):  # type: ignore[no-untyped-def]
        if "verify-image" in argv:
            return RunOutcome(True, 1, "", "FAILED: could not match source")
        return RunOutcome(True, 0, "Verified OK", "")

    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        source_uri="github.com/acme/api",
    )
    report = verify_artifact(
        policy, tools=("slsa-verifier",), runner=runner, which=_all_present,
    )
    assert report.verdict is Verdict.FAIL
    assert report.exit_code == 1
    (result,) = report.results
    assert "could not match source" in result.detail


def test_any_failure_overrides_a_pass() -> None:
    def runner(argv, timeout):  # type: ignore[no-untyped-def]
        if "attestation" in argv:
            return RunOutcome(True, 1, "", "no attestation found")
        return RunOutcome(True, 0, "Verified OK", "")

    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        key="cosign.pub",
        owner="acme",
    )
    report = verify_artifact(policy, runner=runner, which=_all_present)
    # cosign passes, gh fails -> the failure wins.
    assert report.verdict is Verdict.FAIL
    assert report.exit_code == 1


def test_no_binary_available_is_inconclusive() -> None:
    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        source_uri="github.com/acme/api",
        owner="acme",
    )
    report = verify_artifact(
        policy, runner=_passing_runner, which=_none_present,
    )
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.exit_code == 3
    assert all(not r.ran for r in report.results)
    assert any("not found on PATH" in r.detail for r in report.results)


def test_timeout_is_inconclusive_not_fail() -> None:
    # A timed-out verifier is operational, not a "bad artifact" verdict.
    def runner(argv, timeout):  # type: ignore[no-untyped-def]
        return RunOutcome(True, prov.TIMEOUT_RETURNCODE, "", "[timed out after 1s]")

    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3", source_uri="github.com/acme/api",
    )
    report = verify_artifact(
        policy, tools=("slsa-verifier",), runner=runner, which=_all_present,
    )
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.exit_code == 3
    (result,) = report.results
    assert result.ran is False
    assert "timed out" in result.detail


def test_inapplicable_policy_is_inconclusive() -> None:
    # cosign selected but the policy has no key / keyless identity.
    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        source_uri="github.com/acme/api",
    )
    report = verify_artifact(
        policy, tools=("cosign",), runner=_passing_runner, which=_all_present,
    )
    assert report.verdict is Verdict.INCONCLUSIVE
    (result,) = report.results
    assert result.available is True
    assert result.applicable is False
    assert result.ran is False


# ── argv construction ─────────────────────────────────────────────────


def _capture():  # type: ignore[no-untyped-def]
    calls: list[list[str]] = []

    def runner(argv, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(argv))
        return RunOutcome(True, 0, "Verified OK", "")

    return calls, runner


def test_cosign_keyless_argv() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        certificate_identity="signer@acme",
        certificate_oidc_issuer="https://issuer",
    )
    verify_artifact(policy, tools=("cosign",), runner=runner, which=_all_present)
    (argv,) = calls
    assert argv[1:] == [
        "verify",
        "--certificate-identity", "signer@acme",
        "--certificate-oidc-issuer", "https://issuer",
        "ghcr.io/acme/api:1.2.3",
    ]


def test_cosign_keyed_argv() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(ref="ghcr.io/acme/api:1.2.3", key="cosign.pub")
    verify_artifact(policy, tools=("cosign",), runner=runner, which=_all_present)
    (argv,) = calls
    assert argv[1:] == ["verify", "--key", "cosign.pub", "ghcr.io/acme/api:1.2.3"]


def test_slsa_image_argv_with_builder() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(
        ref="ghcr.io/acme/api:1.2.3",
        source_uri="github.com/acme/api",
        builder_id="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generic_generator_slsa3.yml@refs/tags/v2",
    )
    verify_artifact(
        policy, tools=("slsa-verifier",), runner=runner, which=_all_present,
    )
    (argv,) = calls
    assert argv[1] == "verify-image"
    assert "--source-uri" in argv
    assert "--builder-id" in argv


def test_slsa_file_requires_provenance() -> None:
    # is_file + source_uri but no provenance -> not applicable.
    policy = VerifyPolicy(
        ref="dist/app.tar.gz", is_file=True, source_uri="github.com/acme/api",
    )
    report = verify_artifact(
        policy, tools=("slsa-verifier",), runner=_passing_runner,
        which=_all_present,
    )
    (result,) = report.results
    assert result.applicable is False
    assert "provenance" in result.detail


def test_slsa_file_argv() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(
        ref="dist/app.tar.gz", is_file=True,
        source_uri="github.com/acme/api", provenance_path="app.intoto.jsonl",
    )
    verify_artifact(
        policy, tools=("slsa-verifier",), runner=runner, which=_all_present,
    )
    (argv,) = calls
    assert argv[1] == "verify-artifact"
    assert "--provenance-path" in argv
    assert "app.intoto.jsonl" in argv


def test_gh_oci_target_gets_prefix() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(ref="ghcr.io/acme/api:1.2.3", owner="acme")
    verify_artifact(policy, tools=("gh",), runner=runner, which=_all_present)
    (argv,) = calls
    assert argv[1:] == [
        "attestation", "verify", "oci://ghcr.io/acme/api:1.2.3",
        "--owner", "acme",
    ]


def test_gh_file_target_no_prefix() -> None:
    calls, runner = _capture()
    policy = VerifyPolicy(ref="dist/app.tar.gz", is_file=True, owner="acme")
    verify_artifact(policy, tools=("gh",), runner=runner, which=_all_present)
    (argv,) = calls
    assert "oci://" not in " ".join(argv)
    assert "dist/app.tar.gz" in argv


# ── validation ────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad_ref", ["", "   ", "-rf"])
def test_bad_ref_rejected(bad_ref: str) -> None:
    with pytest.raises(ProvenanceError):
        verify_artifact(
            VerifyPolicy(ref=bad_ref, source_uri="github.com/acme/api"),
            runner=_passing_runner, which=_all_present,
        )


def test_flaglike_value_rejected() -> None:
    with pytest.raises(ProvenanceError):
        verify_artifact(
            VerifyPolicy(ref="ghcr.io/acme/api:1", source_uri="--evil"),
            runner=_passing_runner, which=_all_present,
        )


def test_control_char_rejected() -> None:
    with pytest.raises(ProvenanceError):
        verify_artifact(
            VerifyPolicy(ref="ghcr.io/acme/api:1", owner="acme\nrm -rf"),
            runner=_passing_runner, which=_all_present,
        )


def test_unknown_tool_rejected() -> None:
    with pytest.raises(ProvenanceError):
        verify_artifact(
            VerifyPolicy(ref="ghcr.io/acme/api:1", owner="acme"),
            tools=("nope",), runner=_passing_runner, which=_all_present,
        )


# ── helpers ───────────────────────────────────────────────────────────


def test_extract_builder() -> None:
    assert extract_builder(_SLSA_PASS) == (
        "https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1.2.3"
    )
    assert extract_builder("nothing relevant here") is None


def test_default_runner_missing_binary() -> None:
    outcome = default_runner(["pipeline-check-no-such-binary-xyz"], 5)
    assert outcome.found is False
    assert outcome.returncode == 127


# ── CLI surface ───────────────────────────────────────────────────────


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _stub_report(verdict: Verdict, ran: bool = True) -> ProvenanceReport:
    res = ToolResult(
        tool="slsa-verifier", label="slsa-verifier verify-image",
        available=True, applicable=True, ran=ran, ok=verdict is Verdict.PASS,
        returncode=0 if verdict is Verdict.PASS else 1,
        detail="verified" if verdict is Verdict.PASS else "verification failed: x",
        builder="github.com/acme/api/.github/workflows/release.yml@v1" if ran else None,
    )
    return ProvenanceReport(
        ref="ghcr.io/acme/api:1.2.3", verdict=verdict, results=[res],
        builder=res.builder,
    )


def test_cli_missing_ref(runner: CliRunner) -> None:
    result = runner.invoke(verify_artifact_cmd, [])
    assert result.exit_code == 2
    assert "missing REF" in result.output


def test_cli_no_policy(runner: CliRunner) -> None:
    result = runner.invoke(verify_artifact_cmd, ["ghcr.io/acme/api:1.2.3"])
    assert result.exit_code == 2
    assert "no verification policy" in result.output


def test_cli_pass(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prov, "verify_artifact", lambda *a, **k: _stub_report(Verdict.PASS),
    )
    result = runner.invoke(
        verify_artifact_cmd,
        ["ghcr.io/acme/api:1.2.3", "--source-uri", "github.com/acme/api"],
    )
    assert result.exit_code == 0
    assert "PASS" in result.output
    assert "OK" in result.output
    assert "builder:" in result.output


def test_cli_fail(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prov, "verify_artifact", lambda *a, **k: _stub_report(Verdict.FAIL),
    )
    result = runner.invoke(
        verify_artifact_cmd,
        ["ghcr.io/acme/api:1.2.3", "--source-uri", "github.com/acme/api"],
    )
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_cli_inconclusive(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        prov,
        "verify_artifact",
        lambda *a, **k: _stub_report(Verdict.INCONCLUSIVE, ran=False),
    )
    result = runner.invoke(
        verify_artifact_cmd,
        ["ghcr.io/acme/api:1.2.3", "--owner", "acme"],
    )
    assert result.exit_code == 3
    assert "INCONCLUSIVE" in result.output


def test_cli_json(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prov, "verify_artifact", lambda *a, **k: _stub_report(Verdict.PASS),
    )
    result = runner.invoke(
        verify_artifact_cmd,
        ["ghcr.io/acme/api:1.2.3", "--owner", "acme", "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "PASS"
    assert payload["exit_code"] == 0
    assert payload["tools"][0]["tool"] == "slsa-verifier"


def test_cli_oci_prefix_and_file_detection(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    captured: dict[str, VerifyPolicy] = {}

    def stub(policy: VerifyPolicy, **kwargs):  # type: ignore[no-untyped-def]
        captured["policy"] = policy
        return _stub_report(Verdict.PASS)

    monkeypatch.setattr(prov, "verify_artifact", stub)

    # oci:// prefix is stripped, treated as an image.
    runner.invoke(
        verify_artifact_cmd,
        ["oci://ghcr.io/acme/api:1.2.3", "--owner", "acme"],
    )
    assert captured["policy"].ref == "ghcr.io/acme/api:1.2.3"
    assert captured["policy"].is_file is False

    # an existing path auto-detects as a file artifact.
    artifact = tmp_path / "app.tar.gz"
    artifact.write_text("x", encoding="utf-8")
    runner.invoke(
        verify_artifact_cmd,
        [str(artifact), "--owner", "acme"],
    )
    assert captured["policy"].is_file is True


def test_cli_flaglike_ref_is_usage_error(runner: CliRunner) -> None:
    # The real engine validates and raises before any tool runs.
    result = runner.invoke(
        verify_artifact_cmd,
        ["--source-uri=github.com/acme/api", "--", "-rf"],
    )
    assert result.exit_code == 2
