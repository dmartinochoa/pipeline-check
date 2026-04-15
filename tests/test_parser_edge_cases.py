"""Edge-case tests for the three workflow YAML parsers.

Each provider's ``from_path`` loader and check classes are stressed with:
- malformed / empty / binary files
- non-standard root shapes (list, scalar, null)
- directory scans with multiple files
- YAML 1.1 boolean-coercion traps (``on:`` → ``True`` in GHA)
- provider-specific structural quirks (GitLab template jobs, Bitbucket
  parallel steps, image-as-dict, include as mapping vs list, etc.)
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pipeline_check.core.checks.github.base import GitHubContext, workflow_triggers
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext, Pipeline as GLPipeline, iter_jobs as gl_iter_jobs
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.bitbucket.base import BitbucketContext, Pipeline as BBPipeline, iter_steps as bb_iter_steps
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks


def _run(checker_cls, ctx, check_id):
    return next(f for f in checker_cls(ctx).run() if f.check_id == check_id)


def _gitlab_ctx(text: str) -> GitLabContext:
    return GitLabContext([GLPipeline(path="t.yml", data=yaml.safe_load(text))])


def _bitbucket_ctx(text: str) -> BitbucketContext:
    return BitbucketContext([BBPipeline(path="t.yml", data=yaml.safe_load(text))])


# ────────────────────────────────────────────────────────────────────────────
# Loader resilience — malformed, empty, binary, missing
# ────────────────────────────────────────────────────────────────────────────


class TestLoaderResilience:
    def test_github_skips_malformed_yaml(self, tmp_path):
        (tmp_path / "bad.yml").write_text("jobs: [unterminated\n")
        (tmp_path / "ok.yml").write_text("on: push\njobs: {b: {runs-on: x}}\n")
        ctx = GitHubContext.from_path(tmp_path)
        assert [w.path.endswith("ok.yml") for w in ctx.workflows] == [True]

    def test_github_skips_non_dict_root(self, tmp_path):
        (tmp_path / "list.yml").write_text("- one\n- two\n")
        (tmp_path / "scalar.yml").write_text("just-a-string\n")
        (tmp_path / "null.yml").write_text("\n")
        ctx = GitHubContext.from_path(tmp_path)
        assert ctx.workflows == []

    def test_github_skips_binary_file(self, tmp_path):
        (tmp_path / "blob.yml").write_bytes(b"\xff\xfe\x00binary")
        (tmp_path / "ok.yml").write_text("on: push\njobs: {b: {runs-on: x}}\n")
        ctx = GitHubContext.from_path(tmp_path)
        assert len(ctx.workflows) == 1

    def test_github_missing_path_raises(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            GitHubContext.from_path(tmp_path / "does-not-exist")

    def test_gitlab_skips_binary_file(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_bytes(b"\xff\xfebinary")
        ctx = GitLabContext.from_path(tmp_path)
        assert ctx.pipelines == []

    def test_gitlab_falls_back_to_any_yaml(self, tmp_path):
        (tmp_path / "build.yml").write_text("build: {script: [make]}\n")
        ctx = GitLabContext.from_path(tmp_path)
        assert len(ctx.pipelines) == 1

    def test_gitlab_missing_path_raises(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            GitLabContext.from_path(tmp_path / "nope")

    def test_bitbucket_skips_binary_file(self, tmp_path):
        (tmp_path / "bitbucket-pipelines.yml").write_bytes(b"\xff\xfe\x00")
        ctx = BitbucketContext.from_path(tmp_path)
        assert ctx.pipelines == []

    def test_bitbucket_skips_malformed_yaml(self, tmp_path):
        (tmp_path / "bitbucket-pipelines.yml").write_text("pipelines: [unterminated\n")
        ctx = BitbucketContext.from_path(tmp_path)
        assert ctx.pipelines == []

    def test_bitbucket_missing_path_raises(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            BitbucketContext.from_path(tmp_path / "nope")


# ────────────────────────────────────────────────────────────────────────────
# GitHub edge cases
# ────────────────────────────────────────────────────────────────────────────


class TestGitHubEdgeCases:
    def test_yaml_1_1_on_coerced_to_true(self):
        """YAML 1.1 parses bareword ``on`` as boolean True. workflow_triggers
        must normalise this back to the event list."""
        wf = yaml.safe_load("on: push\njobs: {b: {runs-on: x}}\n")
        # pyyaml ≥ 6.0 treats `on:` as literal "on" string under safe_load,
        # but older parsers / some config surfaces may coerce. Exercise both.
        assert workflow_triggers({"on": "push"}) == ["push"]
        assert workflow_triggers({True: "push"}) == ["push"]

    def test_on_list_form(self):
        assert workflow_triggers({"on": ["push", "pull_request"]}) == ["push", "pull_request"]

    def test_on_mapping_form(self):
        triggers = workflow_triggers({"on": {"push": {"branches": ["main"]}}})
        assert triggers == ["push"]

    def test_on_missing_returns_empty(self):
        assert workflow_triggers({}) == []

    def test_gha001_ignores_docker_and_local_refs(self, tmp_path):
        (tmp_path / "w.yml").write_text(
            "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: docker://alpine:latest\n"
            "      - uses: ./local-action\n"
        )
        ctx = GitHubContext.from_path(tmp_path)
        f = _run(WorkflowChecks, ctx, "GHA-001")
        assert f.passed

    def test_gha002_pass_when_no_pr_target(self):
        ctx = GitHubContext.from_path("tests/fixtures/workflows/github/secure-release.yml")
        f = _run(WorkflowChecks, ctx, "GHA-002")
        assert f.passed
        assert "not triggered" in f.description.lower()

    def test_gha004_toplevel_permissions_satisfies_all_jobs(self):
        ctx = GitHubContext([
            __import__("pipeline_check.core.checks.github.base",
                       fromlist=["Workflow"]).Workflow(
                path="x.yml",
                data=yaml.safe_load(
                    "on: push\npermissions: {contents: read}\n"
                    "jobs:\n  a: {runs-on: x, steps: [{run: echo}]}\n"
                    "  b: {runs-on: x, steps: [{run: echo}]}\n"
                ),
            ),
        ])
        f = _run(WorkflowChecks, ctx, "GHA-004")
        assert f.passed


# ────────────────────────────────────────────────────────────────────────────
# GitLab edge cases
# ────────────────────────────────────────────────────────────────────────────


class TestGitLabEdgeCases:
    def test_iter_jobs_skips_keywords_and_templates(self):
        doc = yaml.safe_load(
            """
            variables: {X: 1}
            stages: [build]
            default: {image: python}
            .template:
              script: [echo "hidden"]
            real_job:
              stage: build
              script: [echo ok]
            """
        )
        names = [n for n, _ in gl_iter_jobs(doc)]
        assert names == ["real_job"]

    def test_gl001_image_as_dict_with_name(self):
        ctx = _gitlab_ctx(
            "image:\n  name: python:3.12.1\n  entrypoint: ['']\n"
            "build: {script: [make]}\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-001").passed

    def test_gl001_registry_with_port(self):
        ctx = _gitlab_ctx(
            "build:\n  image: registry.example.com:5000/python:3.12.1\n"
            "  script: [make]\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-001").passed

    def test_gl001_registry_port_but_no_tag(self):
        ctx = _gitlab_ctx(
            "build:\n  image: registry.example.com:5000/python\n"
            "  script: [make]\n"
        )
        assert not _run(GitLabPipelineChecks, ctx, "GL-001").passed

    def test_gl002_single_quoted_still_flagged(self):
        """GitLab interpolates CI variables before shell, so single quotes
        don't make it safe."""
        ctx = _gitlab_ctx(
            "build:\n  script:\n    - echo '$CI_COMMIT_MESSAGE'\n"
        )
        assert not _run(GitLabPipelineChecks, ctx, "GL-002").passed

    def test_gl003_variable_with_description_form(self):
        ctx = _gitlab_ctx(
            "variables:\n"
            "  MY_KEY:\n"
            "    value: AKIAIOSFODNN7EXAMPLE\n"
            "    description: 'oops'\n"
            "build: {script: [make]}\n"
        )
        assert not _run(GitLabPipelineChecks, ctx, "GL-003").passed

    def test_gl003_empty_variables_passes(self):
        ctx = _gitlab_ctx("variables: {}\nbuild: {script: [make]}\n")
        assert _run(GitLabPipelineChecks, ctx, "GL-003").passed

    def test_gl004_rules_manual_counts_as_gated(self):
        ctx = _gitlab_ctx(
            "deploy_prod:\n"
            "  stage: deploy\n"
            "  script: [./deploy.sh]\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == \"main\"'\n"
            "      when: manual\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-004").passed

    def test_gl004_environment_string_form(self):
        ctx = _gitlab_ctx(
            "deploy_prod:\n"
            "  stage: deploy\n"
            "  script: [./deploy.sh]\n"
            "  environment: production\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-004").passed

    def test_gl005_include_as_mapping(self):
        ctx = _gitlab_ctx(
            "include:\n  local: 'ci/extra.yml'\n"
            "build: {script: [make]}\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-005").passed

    def test_gl005_remote_always_flagged(self):
        ctx = _gitlab_ctx(
            "include:\n"
            "  - remote: 'https://example.com/ci.yml?ref=abcdef'\n"
            "build: {script: [make]}\n"
        )
        # Remote includes cannot be cryptographically pinned — always flagged.
        assert not _run(GitLabPipelineChecks, ctx, "GL-005").passed

    def test_gl005_shorthand_string_local_passes(self):
        ctx = _gitlab_ctx(
            "include:\n  - '.gitlab/ci-extra.yml'\n"
            "build: {script: [make]}\n"
        )
        assert _run(GitLabPipelineChecks, ctx, "GL-005").passed

    def test_gl005_shorthand_string_remote_fails(self):
        ctx = _gitlab_ctx(
            "include:\n  - 'https://example.com/ci.yml'\n"
            "build: {script: [make]}\n"
        )
        assert not _run(GitLabPipelineChecks, ctx, "GL-005").passed


# ────────────────────────────────────────────────────────────────────────────
# Bitbucket edge cases
# ────────────────────────────────────────────────────────────────────────────


class TestBitbucketEdgeCases:
    def test_iter_steps_across_all_categories(self):
        doc = yaml.safe_load(
            """
            pipelines:
              default:
                - step: {name: a, script: [echo]}
              branches:
                main:
                  - step: {name: b, script: [echo]}
              pull-requests:
                '**':
                  - step: {name: c, script: [echo]}
              custom:
                nightly:
                  - step: {name: d, script: [echo]}
              tags:
                'v*':
                  - step: {name: e, script: [echo]}
            """
        )
        names = [step.get("name") for _, step in bb_iter_steps(doc)]
        assert sorted(names) == ["a", "b", "c", "d", "e"]

    def test_iter_steps_parallel_list_form(self):
        doc = yaml.safe_load(
            """
            pipelines:
              default:
                - parallel:
                    - step: {name: a, script: [echo]}
                    - step: {name: b, script: [echo]}
            """
        )
        locs = [loc for loc, _ in bb_iter_steps(doc)]
        assert len(locs) == 2
        assert all("parallel" in loc for loc in locs)

    def test_iter_steps_parallel_dict_form(self):
        doc = yaml.safe_load(
            """
            pipelines:
              default:
                - parallel:
                    fail-fast: true
                    steps:
                      - step: {name: a, script: [echo]}
                      - step: {name: b, script: [echo]}
            """
        )
        names = [step.get("name") for _, step in bb_iter_steps(doc)]
        assert names == ["a", "b"]

    def test_iter_steps_stage_form(self):
        doc = yaml.safe_load(
            """
            pipelines:
              default:
                - stage:
                    name: build
                    steps:
                      - step: {name: a, script: [echo]}
                      - step: {name: b, script: [echo]}
            """
        )
        names = [step.get("name") for _, step in bb_iter_steps(doc)]
        assert names == ["a", "b"]

    def test_bb001_pipe_as_dict_with_variables(self):
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - step:
                    max-time: 5
                    script:
                      - pipe: atlassian/aws-s3-deploy:1.4.0
                        variables:
                          S3_BUCKET: 'x'
            """
        )
        assert _run(BitbucketPipelineChecks, ctx, "BB-001").passed

    def test_bb002_single_quoted_still_flagged(self):
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - step:
                    script:
                      - echo '$BITBUCKET_BRANCH'
            """
        )
        assert not _run(BitbucketPipelineChecks, ctx, "BB-002").passed

    def test_bb003_no_variables_block_passes(self):
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - step: {script: [make]}
            """
        )
        assert _run(BitbucketPipelineChecks, ctx, "BB-003").passed

    def test_bb004_deploy_detected_via_pipe(self):
        """A step named neutrally but running a deploy-style pipe should be
        flagged when `deployment:` is missing."""
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - step:
                    name: ship-it
                    script:
                      - pipe: atlassian/aws-s3-deploy:1.4.0
                        variables:
                          S3_BUCKET: 'x'
            """
        )
        assert not _run(BitbucketPipelineChecks, ctx, "BB-004").passed

    def test_bb005_max_time_on_every_step_passes_even_across_parallel(self):
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - parallel:
                    - step: {max-time: 5, script: [echo]}
                    - step: {max-time: 5, script: [echo]}
            """
        )
        assert _run(BitbucketPipelineChecks, ctx, "BB-005").passed

    def test_bb005_partial_max_time_fails(self):
        ctx = _bitbucket_ctx(
            """
            pipelines:
              default:
                - step: {max-time: 5, script: [echo]}
                - step: {script: [echo]}
            """
        )
        assert not _run(BitbucketPipelineChecks, ctx, "BB-005").passed


# ────────────────────────────────────────────────────────────────────────────
# Multi-file directory scans — all three loaders accept a directory
# ────────────────────────────────────────────────────────────────────────────


class TestDirectoryScans:
    def test_github_scans_multiple_workflows(self, tmp_path):
        (tmp_path / "a.yml").write_text("on: push\njobs: {a: {runs-on: x}}\n")
        (tmp_path / "b.yaml").write_text("on: push\njobs: {b: {runs-on: x}}\n")
        ctx = GitHubContext.from_path(tmp_path)
        assert len(ctx.workflows) == 2

    def test_gitlab_prefers_gitlab_ci_yml(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [make]}\n")
        (tmp_path / "other.yml").write_text("unrelated: true\n")
        ctx = GitLabContext.from_path(tmp_path)
        # When .gitlab-ci.yml is present, only it is loaded (not fallback).
        paths = [p.path for p in ctx.pipelines]
        assert any(p.endswith(".gitlab-ci.yml") for p in paths)
        assert not any(p.endswith("other.yml") for p in paths)

    def test_bitbucket_finds_pipelines_yml(self, tmp_path):
        (tmp_path / "bitbucket-pipelines.yml").write_text(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n"
        )
        (tmp_path / "README.yml").write_text("nope: true\n")
        ctx = BitbucketContext.from_path(tmp_path)
        paths = [p.path for p in ctx.pipelines]
        assert any(p.endswith("bitbucket-pipelines.yml") for p in paths)
        assert len(ctx.pipelines) == 1
