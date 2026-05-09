"""Tests for the opt-in AI-augmented explain layer.

The contract these lock in is non-obvious and load-bearing:

- The deterministic ``--explain`` body is ALWAYS what users get;
  the AI section is strictly additive and clearly framed.
- An AI provider's optional dependency or missing key surfaces as
  a clean exit-code-4 error message, never a stack trace.
- The prompt the LLM sees contains the rule's metadata + project
  context; it never silently leaks scan output, env vars, or
  unexpected file contents.

Tests use a stub ``AIClient`` so no real network calls happen.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import ai_explain
from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.rule import Rule

# ── Stub provider ─────────────────────────────────────────────────


@dataclass(slots=True)
class _StubClient:
    """In-process AI client used by the unit tests.

    Captures the system + user prompt the production code constructs
    so the prompt-shape assertions can verify what the model would
    actually see, without sending bytes anywhere.
    """
    name: str = "stub:test"
    response: str = "stubbed-response"
    last_system: str = ""
    last_user: str = ""

    def complete(self, system: str, user: str) -> str:
        self.last_system = system
        self.last_user = user
        return self.response


# ── Spec parsing ──────────────────────────────────────────────────


class TestParseSpec:
    @pytest.mark.parametrize("spec,provider,model", [
        ("anthropic", "anthropic", "claude-sonnet-4-6"),
        ("openai", "openai", "gpt-4o-mini"),
        ("ollama", "ollama", "llama3.2"),
        ("anthropic:claude-opus-4-7", "anthropic", "claude-opus-4-7"),
        ("ollama:llama3.2:latest", "ollama", "llama3.2:latest"),
        # Casing on the provider half is normalized, model half is preserved.
        ("ANTHROPIC:Claude-Sonnet-4-6", "anthropic", "Claude-Sonnet-4-6"),
    ])
    def test_round_trips_known_providers(self, spec, provider, model):
        parsed = ai_explain._parse_spec(spec)
        assert parsed.provider == provider
        assert parsed.model == model

    @pytest.mark.parametrize("bad", [
        "",                   # empty
        "claude-sonnet-4-6",  # bare model name, no provider prefix
        "huggingface",        # not a registered provider
    ])
    def test_rejects_unknown(self, bad):
        with pytest.raises(ValueError):
            ai_explain._parse_spec(bad)


# ── select_client dispatch ────────────────────────────────────────


class TestSelectClient:
    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="unknown AI provider"):
            ai_explain.select_client("notarealprovider")

    def test_anthropic_dependency_or_auth_path(self, monkeypatch):
        # Strip any real env so the path is deterministic. The test
        # accepts either of the two error shapes the constructor can
        # raise: dependency-missing OR auth-missing — whichever the
        # local environment surfaces first.
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(
            (ai_explain.AIDependencyError, ai_explain.AIAuthError)
        ):
            ai_explain.select_client("anthropic")

    def test_openai_dependency_or_auth_path(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(
            (ai_explain.AIDependencyError, ai_explain.AIAuthError)
        ):
            ai_explain.select_client("openai")

    def test_ollama_constructs_without_key(self, monkeypatch):
        # Ollama has no auth requirement at construct time; the
        # connection check happens inside ``complete``. Make sure
        # we can wire one up cleanly so the offline / local-only
        # path works for users without a hosted-provider key.
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        client = ai_explain.select_client("ollama")
        assert client.name.startswith("ollama:")


# ── default_spec_from_env ────────────────────────────────────────


class TestDefaultSpecFromEnv:
    def test_explicit_var_wins(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_CHECK_AI_MODEL", "openai:gpt-4o")
        # Even if a hosted key is set, the explicit override takes
        # precedence — that's the operator's "I picked one" signal.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert ai_explain.default_spec_from_env() == "openai:gpt-4o"

    def test_anthropic_key_wins_over_openai_when_both_set(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_CHECK_AI_MODEL", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthro")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        assert ai_explain.default_spec_from_env() == "anthropic"

    def test_returns_none_when_no_env(self, monkeypatch):
        for k in (
            "PIPELINE_CHECK_AI_MODEL",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "OLLAMA_HOST",
        ):
            monkeypatch.delenv(k, raising=False)
        assert ai_explain.default_spec_from_env() is None


# ── Prompt construction ──────────────────────────────────────────


def _rule(**overrides):
    base = dict(
        id="GHA-001",
        title="Action not pinned to commit SHA",
        severity=Severity.HIGH,
        recommendation="Pin to a commit SHA.",
        docs_note=(
            "Detects ``actions/checkout@v4`` style refs that pin to a "
            "tag or branch rather than a commit SHA."
        ),
        known_fp=("Internal first-party actions are pinned to a tag "
                  "by convention; treat the LOW-confidence default as "
                  "the right level for those.",),
        cwe=("CWE-494", "CWE-829"),
    )
    base.update(overrides)
    return Rule(**base)


class TestPromptBuilder:
    def test_includes_rule_metadata(self):
        prompt = ai_explain.build_user_prompt(_rule())
        assert "GHA-001" in prompt
        assert "HIGH" in prompt
        assert "Pin to a commit SHA" in prompt
        assert "CWE-494" in prompt
        # Known-FP modes get included so the model can suppress its
        # own false positives ahead of time.
        assert "Known false-positive modes" in prompt
        assert "Internal first-party actions" in prompt

    def test_includes_project_summary_when_provided(self):
        prompt = ai_explain.build_user_prompt(
            _rule(),
            project_summary="# pipeline-check\nA CI/CD security scanner.",
        )
        assert "Project context" in prompt
        assert "pipeline-check" in prompt

    def test_omits_project_summary_when_empty(self):
        prompt = ai_explain.build_user_prompt(_rule(), project_summary="")
        assert "Project context" not in prompt

    def test_includes_file_excerpt_with_path_label(self):
        prompt = ai_explain.build_user_prompt(
            _rule(),
            file_excerpt="uses: actions/checkout@v4\n",
            file_path=".github/workflows/ci.yml",
        )
        assert ".github/workflows/ci.yml" in prompt
        assert "actions/checkout@v4" in prompt
        # Code fences ground the excerpt as code, not prose.
        assert "```" in prompt

    def test_no_file_excerpt_falls_back_to_generic_note(self):
        prompt = ai_explain.build_user_prompt(_rule())
        assert "No offending file provided" in prompt


class TestReadReadme:
    def test_reads_first_n_lines(self, tmp_path):
        readme = tmp_path / "README.md"
        readme.write_text("\n".join(f"line {i}" for i in range(200)) + "\n")
        out = ai_explain.read_readme(str(tmp_path), limit_lines=10)
        assert out.count("\n") == 9  # 10 lines = 9 newlines between
        assert "line 0" in out
        assert "line 9" in out
        assert "line 10" not in out

    def test_returns_empty_when_missing(self, tmp_path):
        assert ai_explain.read_readme(str(tmp_path)) == ""


class TestReadFileExcerpt:
    def test_reads_first_n_lines(self, tmp_path):
        f = tmp_path / "wf.yml"
        f.write_text("\n".join(f"step {i}" for i in range(500)) + "\n")
        out = ai_explain.read_file_excerpt(str(f), limit_lines=50)
        assert "step 0" in out
        assert "step 49" in out
        assert "step 50" not in out

    def test_returns_empty_for_missing_file(self, tmp_path):
        assert ai_explain.read_file_excerpt(str(tmp_path / "nope.yml")) == ""


# ── End-to-end via stub client ────────────────────────────────────


class TestExplainCheck:
    def test_routes_through_client_complete(self, tmp_path):
        client = _StubClient(response="here is what to fix")
        out = ai_explain.explain_check(
            _rule(), client=client, repo_path=str(tmp_path),
        )
        assert out == "here is what to fix"
        assert "GHA-001" in client.last_user

    def test_grounds_in_repo_readme(self, tmp_path):
        (tmp_path / "README.md").write_text(
            "# my-app\nA Django service deployed on ECS.\n"
        )
        client = _StubClient()
        ai_explain.explain_check(
            _rule(), client=client, repo_path=str(tmp_path),
        )
        assert "my-app" in client.last_user
        assert "ECS" in client.last_user

    def test_grounds_in_context_file(self, tmp_path):
        wf = tmp_path / "ci.yml"
        wf.write_text("uses: actions/checkout@v4\n")
        client = _StubClient()
        ai_explain.explain_check(
            _rule(), client=client, repo_path=str(tmp_path),
            context_file=str(wf),
        )
        assert "actions/checkout@v4" in client.last_user

    def test_request_error_propagates(self, tmp_path):
        class _Failing:
            name = "stub:fail"

            def complete(self, system, user):
                raise ai_explain.AIRequestError("boom")

        with pytest.raises(ai_explain.AIRequestError, match="boom"):
            ai_explain.explain_check(
                _rule(), client=_Failing(), repo_path=str(tmp_path),
            )


# ── render_section framing ───────────────────────────────────────


class TestRenderSection:
    def test_carries_provider_label_and_banner(self):
        framed = ai_explain.render_section("anthropic:claude-sonnet-4-6", "ok")
        assert "[AI-generated" in framed
        assert "non-deterministic" in framed
        assert "anthropic:claude-sonnet-4-6" in framed
        assert "ok" in framed

    def test_handles_empty_response(self):
        framed = ai_explain.render_section("ollama:llama3.2", "")
        assert "(model returned an empty response)" in framed


# ── CLI integration ──────────────────────────────────────────────


class TestCliFlag:
    """Cover the ``--ai-explain`` flag's dispatch and error paths.

    Uses ``monkeypatch`` to substitute a stub client so the test
    suite never reaches a real LLM.
    """

    def _patch_stub(self, monkeypatch, response="ai output here"):
        stub = _StubClient(response=response)
        monkeypatch.setattr(
            ai_explain, "select_client", lambda spec: stub,
        )
        monkeypatch.setenv("PIPELINE_CHECK_AI_MODEL", "stub")
        return stub

    def test_emits_deterministic_then_ai_section(self, monkeypatch):
        self._patch_stub(monkeypatch)
        runner = CliRunner()
        result = runner.invoke(scan, ["--ai-explain", "GHA-001"])
        assert result.exit_code == 0, result.output
        # Deterministic body comes first (shows the standards block).
        assert "GHA-001" in result.output
        # AI banner clearly separates the section.
        assert "[AI-generated" in result.output
        # The banner names the provider.
        assert "stub:test" in result.output
        # And the stubbed body shows up.
        assert "ai output here" in result.output

    def test_unknown_check_id_short_circuits_with_exit_3(self, monkeypatch):
        # No AI call should happen for an unknown ID — the
        # deterministic ``--explain`` returns 3 first.
        stub = self._patch_stub(monkeypatch)
        runner = CliRunner()
        result = runner.invoke(scan, ["--ai-explain", "DOES-NOT-EXIST"])
        assert result.exit_code == 3
        # The stub must not have been called.
        assert stub.last_user == ""

    def test_no_provider_configured_exits_4(self, monkeypatch):
        # Strip every signal the default-resolver looks at.
        for k in (
            "PIPELINE_CHECK_AI_MODEL",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "OLLAMA_HOST",
        ):
            monkeypatch.delenv(k, raising=False)
        runner = CliRunner()
        result = runner.invoke(scan, ["--ai-explain", "GHA-001"])
        assert result.exit_code == 4
        assert "no AI provider configured" in result.output

    def test_dependency_error_surfaces_install_hint(self, monkeypatch):
        def _raises(spec):
            raise ai_explain.AIDependencyError(
                "Anthropic provider requires the ``anthropic`` SDK. "
                "Install with ``pip install pipeline-check[ai-anthropic]``."
            )
        monkeypatch.setattr(ai_explain, "select_client", _raises)
        monkeypatch.setenv("PIPELINE_CHECK_AI_MODEL", "anthropic")
        runner = CliRunner()
        result = runner.invoke(scan, ["--ai-explain", "GHA-001"])
        assert result.exit_code == 4
        assert "ai-anthropic" in result.output

    def test_request_error_surfaces_message(self, monkeypatch):
        class _Failing:
            name = "stub:fail"

            def complete(self, system, user):
                raise ai_explain.AIRequestError(
                    "Anthropic API error: 429 rate limit"
                )

        monkeypatch.setattr(
            ai_explain, "select_client", lambda spec: _Failing(),
        )
        monkeypatch.setenv("PIPELINE_CHECK_AI_MODEL", "anthropic")
        runner = CliRunner()
        result = runner.invoke(scan, ["--ai-explain", "GHA-001"])
        assert result.exit_code == 4
        assert "rate limit" in result.output

    def test_context_file_flag_is_passed_through(self, monkeypatch, tmp_path):
        wf = tmp_path / "ci.yml"
        wf.write_text("uses: actions/checkout@v4\n")
        stub = self._patch_stub(monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            scan,
            ["--ai-explain", "GHA-001", "--ai-context-file", str(wf)],
        )
        assert result.exit_code == 0, result.output
        assert "actions/checkout@v4" in stub.last_user

    def test_context_file_must_exist(self, monkeypatch):
        # Click's ``type=click.Path(exists=True, ...)`` should reject
        # a missing file before the AI path runs.
        self._patch_stub(monkeypatch)
        runner = CliRunner()
        result = runner.invoke(
            scan,
            ["--ai-explain", "GHA-001", "--ai-context-file", "no-such-file.yml"],
        )
        assert result.exit_code != 0
        assert "no-such-file.yml" in result.output


# ── Determinism contract ─────────────────────────────────────────


class TestDeterminismContract:
    """The deterministic ``--explain`` and ``--list-checks`` paths
    must NOT change shape based on AI flag presence.

    These tests guard the boundary that makes the AI augmentation
    safe to ship: a CI gate that consumes ``--explain`` output, or
    a SARIF-driven dashboard, never sees AI content unless an
    operator explicitly asked for it.
    """

    def test_explain_unchanged_without_ai_flag(self, monkeypatch):
        # The plain ``--explain`` path must not contain the AI banner.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        runner = CliRunner()
        result = runner.invoke(scan, ["--explain", "GHA-001"])
        assert result.exit_code == 0
        assert "[AI-generated" not in result.output

    def test_no_ai_call_unless_flag_passed(self, monkeypatch):
        called = {"yes": False}

        def _watch(spec):
            called["yes"] = True
            return _StubClient()

        monkeypatch.setattr(ai_explain, "select_client", _watch)
        monkeypatch.setenv("PIPELINE_CHECK_AI_MODEL", "stub")

        runner = CliRunner()
        # A regular ``--explain`` run, no AI flag, must never call
        # select_client even if a default provider is configured.
        runner.invoke(scan, ["--explain", "GHA-001"])
        assert called["yes"] is False
