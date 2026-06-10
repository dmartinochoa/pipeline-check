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
