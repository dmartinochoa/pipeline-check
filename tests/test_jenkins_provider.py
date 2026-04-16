"""Focused tests for the Jenkins provider — CLI integration, parser
edge cases, and per-check sad paths the broad fixture sweep doesn't
exercise.

Snippets live on disk under ``tests/fixtures/scenarios/jenkins/`` so
the inline triple-quoted Groovy that used to fill this file is now
in real ``.jenkinsfile`` files an IDE can syntax-highlight.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import providers as providers_mod
from pipeline_check.core.checks.jenkins.base import JenkinsContext, _extract_stages
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks


SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenarios" / "jenkins"


def _scenario(name: str) -> str:
    """Return the body of a Jenkins scenario fixture by filename."""
    return (SCENARIO_DIR / name).read_text(encoding="utf-8")


def _scan_text(text: str, tmp_path: Path):
    """Helper: write *text* to a Jenkinsfile and return ``{check_id: passed}``."""
    p = tmp_path / "Jenkinsfile"
    p.write_text(text, encoding="utf-8")
    ctx = JenkinsContext.from_path(p)
    return {f.check_id: f.passed for f in JenkinsfileChecks(ctx).run()}


def _scan(name: str, tmp_path: Path):
    """Convenience: load + scan a scenario in one call."""
    return _scan_text(_scenario(name), tmp_path)


# ────────────────────────────────────────────────────────────────────────
# Provider registration + CLI integration
# ────────────────────────────────────────────────────────────────────────


def test_jenkins_provider_is_registered():
    """The provider registry must include jenkins so ``--pipeline jenkins``
    resolves at the CLI layer."""
    assert "jenkins" in providers_mod.available()
    assert providers_mod.get("jenkins") is not None


def test_cli_autodetects_jenkinsfile(tmp_path, monkeypatch):
    """Running ``pipeline_check --pipeline jenkins`` with no path argument
    should pick up ``./Jenkinsfile`` and announce the auto-detect on stderr,
    mirroring the other workflow providers."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Jenkinsfile").write_text("pipeline { agent any }\n", encoding="utf-8")
    result = CliRunner().invoke(scan, ["--pipeline", "jenkins", "--output", "json"])
    assert result.exit_code in (0, 1), result.output
    assert "[auto] using --jenkinsfile-path Jenkinsfile" in result.output


def test_cli_missing_jenkinsfile_raises_usage_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no Jenkinsfile present
    result = CliRunner().invoke(scan, ["--pipeline", "jenkins"])
    assert result.exit_code != 0
    assert "--jenkinsfile-path" in result.output


def test_cli_explicit_path_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        scan, ["--pipeline", "jenkins", "--jenkinsfile-path", "nope/Jenkinsfile"]
    )
    assert result.exit_code != 0
    assert "not found" in result.output


# ────────────────────────────────────────────────────────────────────────
# Loader edge cases
# ────────────────────────────────────────────────────────────────────────


def test_loader_picks_up_jenkinsfile_groovy_extension(tmp_path):
    """Files ending in ``.groovy`` and ``.jenkinsfile`` should also be
    parsed when a directory is passed — monorepo conventions vary."""
    (tmp_path / "build.jenkinsfile").write_text("pipeline { agent any }\n")
    (tmp_path / "deploy.groovy").write_text("pipeline { agent any }\n")
    ctx = JenkinsContext.from_path(tmp_path)
    names = sorted(Path(f.path).name for f in ctx.files)
    assert names == ["build.jenkinsfile", "deploy.groovy"]


def test_loader_skips_unreadable_file(tmp_path, monkeypatch):
    """A file we can't decode as UTF-8 must be skipped silently rather
    than crashing the whole scan — matches the loader contract for the
    YAML providers."""
    p = tmp_path / "Jenkinsfile"
    p.write_bytes(b"\xff\xfe\xff\xfe not valid utf-8 \xc3\x28")
    ctx = JenkinsContext.from_path(p)
    # The file resolved but couldn't be decoded; loader returns no entry.
    assert ctx.files == []


def test_loader_raises_on_missing_path():
    with pytest.raises(ValueError, match="does not exist"):
        JenkinsContext.from_path("/definitely/not/a/path/Jenkinsfile")


def test_extract_stages_handles_nested_braces():
    """A stage body containing ``script { … }`` and ``steps { … }``
    nested blocks must be captured in full — the depth-aware walker
    is the whole reason we don't use a flat regex."""
    text = _scenario("extract-stages-nested-braces.jenkinsfile")
    stages = _extract_stages(text)
    assert len(stages) == 1
    name, body = stages[0]
    assert name == "Build"
    # Both nested blocks must be visible inside the captured body.
    assert "script {" in body
    assert "if (x) {" in body
    assert "make" in body


def test_extract_stages_unclosed_brace_returns_truncated_body():
    """A pathologically unbalanced stage block (missing closing brace)
    shouldn't blow up — the walker should yield what it has so the
    rest of the checks still run."""
    text = _scenario("extract-stages-unclosed.jenkinsfile")
    stages = _extract_stages(text)
    assert stages
    assert stages[0][0] == "Broken"


# ────────────────────────────────────────────────────────────────────────
# JF-009 — docker image pinning
# ────────────────────────────────────────────────────────────────────────


def test_jf009_passes_with_digest_pin(tmp_path):
    assert _scan("jf009-digest-pin.jenkinsfile", tmp_path)["JF-009"] is True


def test_jf009_flags_floating_tag(tmp_path):
    assert _scan("jf009-floating-tag.jenkinsfile", tmp_path)["JF-009"] is False


def test_jf009_flags_no_tag(tmp_path):
    assert _scan("jf009-no-tag.jenkinsfile", tmp_path)["JF-009"] is False


def test_jf009_flags_version_tag_without_digest(tmp_path):
    """Tag-pinned but not digest-pinned still fails — registry tag
    repointing is the threat model."""
    assert _scan("jf009-version-tag.jenkinsfile", tmp_path)["JF-009"] is False


def test_jf009_passes_when_no_docker_agent(tmp_path):
    assert _scan("jf009-no-docker-agent.jenkinsfile", tmp_path)["JF-009"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-010 — env-block AWS keys
# ────────────────────────────────────────────────────────────────────────


def test_jf010_credentials_reference_passes(tmp_path):
    """``credentials('id')`` reads from the credentials store at runtime
    and is the recommended pattern — must not be flagged."""
    assert _scan("jf010-credentials-reference.jenkinsfile", tmp_path)["JF-010"] is True


def test_jf010_literal_value_fails(tmp_path):
    assert _scan("jf010-literal-value.jenkinsfile", tmp_path)["JF-010"] is False


def test_jf010_inline_form_flagged(tmp_path):
    """``environment { KEY = '...' }`` on a single line is the most
    compact form in real Jenkinsfiles. Regression test for the
    line-start-anchor bug found by the per-check real-examples sweep."""
    assert _scan("jf010-inline-form.jenkinsfile", tmp_path)["JF-010"] is False


def test_jf010_session_token_also_flagged(tmp_path):
    assert _scan("jf010-session-token.jenkinsfile", tmp_path)["JF-010"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-011 — buildDiscarder retention
# ────────────────────────────────────────────────────────────────────────


def test_jf011_passes_with_options_block(tmp_path):
    assert _scan("jf011-options-block.jenkinsfile", tmp_path)["JF-011"] is True


def test_jf011_passes_with_scripted_properties(tmp_path):
    """Scripted-pipeline equivalent uses ``properties([buildDiscarder(...)])``."""
    assert _scan("jf011-scripted-properties.jenkinsfile", tmp_path)["JF-011"] is True


def test_jf011_passes_with_logrotator_alias(tmp_path):
    """Older Jenkinsfiles call the helper directly."""
    assert _scan("jf011-logrotator-alias.jenkinsfile", tmp_path)["JF-011"] is True


def test_jf011_fails_without_any_retention(tmp_path):
    assert _scan("jf011-no-retention.jenkinsfile", tmp_path)["JF-011"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-012 — load step
# ────────────────────────────────────────────────────────────────────────


def test_jf012_passes_when_no_load_step(tmp_path):
    assert _scan("jf012-no-load-step.jenkinsfile", tmp_path)["JF-012"] is True


def test_jf012_flags_load_inside_script(tmp_path):
    assert _scan("jf012-load-inside-script.jenkinsfile", tmp_path)["JF-012"] is False


def test_jf012_only_matches_groovy_extension(tmp_path):
    """``load 'foo.txt'`` would be a Groovy syntax error in practice;
    the regex deliberately requires a .groovy extension so a `load`
    keyword in some other context (e.g. plugin DSL) doesn't trip it."""
    assert _scan("jf012-load-non-groovy.jenkinsfile", tmp_path)["JF-012"] is True
