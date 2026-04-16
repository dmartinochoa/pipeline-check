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


# ────────────────────────────────────────────────────────────────────────
# JF-001 — library pinning
# ────────────────────────────────────────────────────────────────────────


def test_jf001_flags_no_ref(tmp_path):
    """``@Library('name')`` with no ``@ref`` is floating."""
    assert _scan("jf001-no-ref.jenkinsfile", tmp_path)["JF-001"] is False


def test_jf001_passes_pinned_sha(tmp_path):
    """A 40-char hex SHA is a valid pin."""
    assert _scan("jf001-pinned-sha.jenkinsfile", tmp_path)["JF-001"] is True


def test_jf001_passes_pinned_tag(tmp_path):
    """A semver tag like ``@v1.4.2`` is a valid pin."""
    assert _scan("jf001-pinned-tag.jenkinsfile", tmp_path)["JF-001"] is True


def test_jf001_flags_floating_main(tmp_path):
    """``@main`` is a floating branch ref."""
    assert _scan("jf001-floating-main.jenkinsfile", tmp_path)["JF-001"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-002 — script injection
# ────────────────────────────────────────────────────────────────────────


def test_jf002_safe_single_quotes(tmp_path):
    """Single-quoted Groovy strings don't interpolate — safe."""
    assert _scan("jf002-safe-single-quotes.jenkinsfile", tmp_path)["JF-002"] is True


def test_jf002_unsafe_double_quotes(tmp_path):
    """Double-quoted GString with ``$BRANCH_NAME`` is injectable."""
    assert _scan("jf002-unsafe-double-quotes.jenkinsfile", tmp_path)["JF-002"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-003 — agent isolation
# ────────────────────────────────────────────────────────────────────────


def test_jf003_passes_with_docker_agent(tmp_path):
    """``agent { docker { … } }`` is isolated — passes."""
    assert _scan("jf003-agent-docker.jenkinsfile", tmp_path)["JF-003"] is True


def test_jf003_flags_agent_any(tmp_path):
    """``agent any`` is the broadest scope — fails."""
    result = _scan("jf001-no-ref.jenkinsfile", tmp_path)  # reuse: has agent any
    assert result["JF-003"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-004 — AWS long-lived keys
# ────────────────────────────────────────────────────────────────────────


def test_jf004_flags_with_aws_credentials(tmp_path):
    """``withAWS(credentials: '…')`` uses static credentials — fails."""
    assert _scan("jf004-with-aws-credentials.jenkinsfile", tmp_path)["JF-004"] is False


def test_jf004_passes_with_aws_role(tmp_path):
    """``withAWS(role: '…')`` assumes a short-lived role — passes."""
    assert _scan("jf004-with-aws-role.jenkinsfile", tmp_path)["JF-004"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-005 — deploy approval gate
# ────────────────────────────────────────────────────────────────────────


def test_jf005_no_false_positive_on_development(tmp_path):
    """A stage named 'Development' must not trip the deploy-stage regex.
    Regression test for the word-boundary fix in DEPLOY_RE."""
    assert _scan("jf005-development-stage.jenkinsfile", tmp_path)["JF-005"] is True


def test_jf005_passes_deploy_with_input(tmp_path):
    """A deploy stage with ``input { … }`` is properly gated."""
    assert _scan("jf005-deploy-with-input.jenkinsfile", tmp_path)["JF-005"] is True


def test_jf005_flags_deploy_without_input(tmp_path):
    """A deploy stage without ``input`` is ungated — fails."""
    assert _scan("jf005-deploy-no-input.jenkinsfile", tmp_path)["JF-005"] is False


# ────────────────────────────────────────────────────────────────────────
# JF-006 — artifact signing (comment-stripping)
# ────────────────────────────────────────────────────────────────────────


def test_jf006_cosign_in_comment_does_not_pass(tmp_path):
    """``// TODO: add cosign`` in a comment must not satisfy the check."""
    assert _scan("jf006-cosign-in-comment.jenkinsfile", tmp_path)["JF-006"] is False


def test_jf006_cosign_in_block_comment_does_not_pass(tmp_path):
    """``/* cosign */`` in a block comment must not satisfy the check."""
    assert _scan("jf006-cosign-in-block-comment.jenkinsfile", tmp_path)["JF-006"] is False


def test_jf006_cosign_in_shell_step_passes(tmp_path):
    """``sh 'cosign sign …'`` is a real invocation — passes."""
    assert _scan("jf006-cosign-in-shell.jenkinsfile", tmp_path)["JF-006"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-007 — SBOM (comment-stripping)
# ────────────────────────────────────────────────────────────────────────


def test_jf007_syft_in_comment_does_not_pass(tmp_path):
    """Commented-out syft invocation must not satisfy the check."""
    assert _scan("jf007-syft-in-comment.jenkinsfile", tmp_path)["JF-007"] is False


def test_jf007_syft_active_passes(tmp_path):
    """Active syft invocation passes."""
    assert _scan("jf007-syft-active.jenkinsfile", tmp_path)["JF-007"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-013 — copyArtifacts
# ────────────────────────────────────────────────────────────────────────


def test_jf013_copy_without_verify_fails(tmp_path):
    assert _scan("jf013-copy-no-verify.jenkinsfile", tmp_path)["JF-013"] is False


def test_jf013_copy_with_verify_passes(tmp_path):
    assert _scan("jf013-copy-with-verify.jenkinsfile", tmp_path)["JF-013"] is True


def test_jf013_no_copy_passes(tmp_path):
    """No copyArtifacts at all — passes (nothing to verify)."""
    assert _scan("jf013-no-copy.jenkinsfile", tmp_path)["JF-013"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-014 — ephemeral agent labels
# ────────────────────────────────────────────────────────────────────────


def test_jf014_label_without_ephemeral_fails(tmp_path):
    assert _scan("jf014-label-no-ephemeral.jenkinsfile", tmp_path)["JF-014"] is False


def test_jf014_label_with_ephemeral_passes(tmp_path):
    assert _scan("jf014-label-ephemeral.jenkinsfile", tmp_path)["JF-014"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-019 — sandbox escape
# ────────────────────────────────────────────────────────────────────────


def test_jf019_flags_runtime_getruntime(tmp_path):
    assert _scan("jf019-runtime-getruntime.jenkinsfile", tmp_path)["JF-019"] is False


def test_jf019_flags_grab_annotation(tmp_path):
    assert _scan("jf019-grab-annotation.jenkinsfile", tmp_path)["JF-019"] is False


def test_jf019_clean_passes(tmp_path):
    assert _scan("jf019-clean.jenkinsfile", tmp_path)["JF-019"] is True


# ────────────────────────────────────────────────────────────────────────
# JF-020 — vulnerability scanning (comment-stripping)
# ────────────────────────────────────────────────────────────────────────


def test_jf020_trivy_in_comment_does_not_pass(tmp_path):
    """``/* trivy … */`` in a block comment must not satisfy the check."""
    assert _scan("jf020-trivy-in-comment.jenkinsfile", tmp_path)["JF-020"] is False


def test_jf020_trivy_active_passes(tmp_path):
    """Active trivy invocation passes."""
    assert _scan("jf020-trivy-active.jenkinsfile", tmp_path)["JF-020"] is True


# ────────────────────────────────────────────────────────────────────────
# Stage extraction — string-literal brace handling
# ────────────────────────────────────────────────────────────────────────


def test_extract_stages_skips_braces_in_string_literals():
    """Braces inside string literals (e.g. ``sh 'echo "}"'``) must not
    break the depth count — the stage body should be captured in full."""
    text = _scenario("extract-stages-string-braces.jenkinsfile")
    stages = _extract_stages(text)
    assert len(stages) == 1
    name, body = stages[0]
    assert name == "Build"
    assert "make build" in body


# ────────────────────────────────────────────────────────────────────────
# Comment-stripping helper
# ────────────────────────────────────────────────────────────────────────


def test_strip_groovy_comments_removes_line_comments():
    from pipeline_check.core.checks.jenkins.rules._helpers import strip_groovy_comments
    text = 'sh "make build" // this is a comment\nnext line'
    result = strip_groovy_comments(text)
    assert "this is a comment" not in result
    assert "make build" in result
    assert "next line" in result


def test_strip_groovy_comments_removes_block_comments():
    from pipeline_check.core.checks.jenkins.rules._helpers import strip_groovy_comments
    text = 'before /* cosign sign */ after'
    result = strip_groovy_comments(text)
    assert "cosign" not in result
    assert "before" in result
    assert "after" in result


def test_strip_groovy_comments_preserves_strings():
    from pipeline_check.core.checks.jenkins.rules._helpers import strip_groovy_comments
    text = """sh 'echo // not a comment'\nsh "cosign sign // also preserved" """
    result = strip_groovy_comments(text)
    assert "not a comment" in result
    assert "cosign sign" in result
