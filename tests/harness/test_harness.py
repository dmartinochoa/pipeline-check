"""Tests for the Harness CI/CD provider (HARNESS-*)."""
from __future__ import annotations

from pathlib import Path

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.harness.base import HarnessContext
from pipeline_check.core.checks.harness.pipelines import HarnessPipelineChecks

_DA = "a" * 64
_DB = "b" * 64

# A pipeline exercising nested steps (parallel + stepGroup), an unpinned
# image, a digest-pinned image, and an untrusted-expression command.
_PIPELINE = f"""\
pipeline:
  identifier: build
  name: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    image: node:18
                    shell: Sh
                    command: echo "building <+codebase.prTitle>"
              - parallel:
                  - step:
                      type: Run
                      identifier: lint
                      spec:
                        image: golang@sha256:{_DA}
                        command: go vet ./...
                  - stepGroup:
                      identifier: grp
                      steps:
                        - step:
                            type: Plugin
                            identifier: publish
                            spec:
                              image: plugins/docker:latest
                              settings:
                                repo: my/app
"""

# A clean pipeline: digest-pinned image, command bound via env var.
_CLEAN = f"""\
pipeline:
  identifier: clean
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: test
                  spec:
                    image: node@sha256:{_DB}
                    envVariables:
                      PR_TITLE: <+codebase.prTitle>
                    command: echo "$PR_TITLE"
"""

# A realistically-shaped (fake) leaked GitHub PAT: ghp_ + 36 chars.
_LEAKED_TOKEN = "ghp_016d8d1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"

# A pipeline with a privileged step and a literal-secret String variable
# alongside a properly-referenced Secret variable.
_RISKY = f"""\
pipeline:
  identifier: risky
  variables:
    - name: GH_TOKEN
      type: String
      value: {_LEAKED_TOKEN}
    - name: SAFE_TOKEN
      type: Secret
      value: <+secrets.getValue("gh_token")>
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: dind
                  spec:
                    image: docker@sha256:{_DA}
                    privileged: true
                    command: docker build .
"""

# Not a Harness pipeline (no top-level ``pipeline:`` key): must be skipped.
_NOT_HARNESS = """\
template:
  identifier: t
  type: Step
"""


def _ctx(tmp_path: Path, text: str, name: str = "pipeline.yaml") -> HarnessContext:
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return HarnessContext.from_path(f)


def _findings(ctx: HarnessContext) -> list:
    return HarnessPipelineChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


class TestContextLoad:
    def test_keeps_only_pipeline_documents(self, tmp_path):
        ctx = _ctx(tmp_path, _NOT_HARNESS)
        assert ctx.pipelines == []

    def test_missing_path_raises(self):
        import pytest
        with pytest.raises(ValueError):
            HarnessContext.from_path("/no/such/harness/dir")

    def test_directory_scan_picks_up_yaml(self, tmp_path):
        (tmp_path / ".harness").mkdir()
        (tmp_path / ".harness" / "p.yaml").write_text(_CLEAN, encoding="utf-8")
        ctx = HarnessContext.from_path(tmp_path / ".harness")
        assert len(ctx.pipelines) == 1
        assert ctx.pipelines[0].identifier == "clean"


class TestHarness001ImagePinning:
    def test_flags_unpinned_step_and_plugin_images(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPELINE)), "HARNESS-001")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        # node:18 (Run) and plugins/docker:latest (Plugin, in a stepGroup)
        # are flagged; the digest-pinned golang is not.
        assert "ci/test=node:18" in f.description
        assert "ci/publish=plugins/docker:latest" in f.description
        assert "golang" not in f.description

    def test_passes_when_all_digest_pinned(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-001")
        assert out and all(f.passed for f in out)


class TestHarness002ExpressionInjection:
    def test_flags_untrusted_expression_in_command(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPELINE)), "HARNESS-002")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "ci/test" in f.description
        assert "codebase.prTitle" in f.description

    def test_env_var_binding_is_safe(self, tmp_path):
        # The clean pipeline binds <+codebase.prTitle> to an env var and
        # uses $PR_TITLE in the command; the command text has no expression.
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-002")
        assert out and all(f.passed for f in out)

    def test_commit_sha_not_flagged(self, tmp_path):
        text = _CLEAN.replace(
            'command: echo "$PR_TITLE"',
            'command: echo "<+codebase.commitSha>"',
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-002")
               if not f.passed]
        assert out == []


class TestHarness003PrivilegedStep:
    def test_flags_privileged_step(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _RISKY)), "HARNESS-003")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.HIGH
        assert "ci/dind" in f.description

    def test_passes_without_privileged(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-003")
        assert out and all(f.passed for f in out)

    def test_privileged_false_not_flagged(self, tmp_path):
        text = _RISKY.replace("privileged: true", "privileged: false")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-003")
               if not f.passed]
        assert out == []


class TestHarness004LiteralSecret:
    def test_flags_literal_secret_string_variable(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _RISKY)), "HARNESS-004")
               if not f.passed]
        assert len(out) == 1
        f = out[0]
        assert f.severity is Severity.CRITICAL
        assert "pipeline.GH_TOKEN" in f.description
        # The Secret-typed reference variable is not flagged, and the raw
        # token value is redacted out of the finding.
        assert "SAFE_TOKEN" not in f.description
        assert _LEAKED_TOKEN not in f.description

    def test_secret_reference_is_safe(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-004")
        assert out and all(f.passed for f in out)

    def test_non_secret_string_not_flagged(self, tmp_path):
        text = _RISKY.replace(_LEAKED_TOKEN, "production")
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-004")
               if not f.passed]
        assert out == []


_PIPE = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: install
                  spec:
                    image: alpine
                    command: |
                      curl -fsSL https://example.com/install.sh | sh
"""


class TestHarness005PipeToShell:
    def test_flags_pipe_to_shell(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _PIPE)), "HARNESS-005")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/install" in out[0].description

    def test_download_then_execute_is_safe(self, tmp_path):
        text = _PIPE.replace(
            "curl -fsSL https://example.com/install.sh | sh",
            "curl -fsSL -o i.sh https://example.com/install.sh && sh i.sh",
        )
        out = [f for f in _for(_findings(_ctx(tmp_path, text)), "HARNESS-005")
               if not f.passed]
        assert out == []

    def test_clean_pipeline_passes(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-005")
        assert out and all(f.passed for f in out)


_TLS = """\
pipeline:
  identifier: build
  stages:
    - stage:
        identifier: ci
        type: CI
        spec:
          execution:
            steps:
              - step:
                  type: Run
                  identifier: install
                  spec:
                    image: node
                    command: |
                      npm config set strict-ssl false
                      npm install
"""


class TestHarness006TlsBypass:
    def test_flags_tls_bypass(self, tmp_path):
        out = [f for f in _for(_findings(_ctx(tmp_path, _TLS)), "HARNESS-006")
               if not f.passed]
        assert len(out) == 1
        assert out[0].severity is Severity.HIGH
        assert "ci/install" in out[0].description

    def test_clean_pipeline_passes(self, tmp_path):
        out = _for(_findings(_ctx(tmp_path, _CLEAN)), "HARNESS-006")
        assert out and all(f.passed for f in out)
