"""TKN-016. Remote resolver / bundle taskRef / pipelineRef not pinned."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.tekton.base import TektonContext
from pipeline_check.core.checks.tekton.rules.tkn016_remote_resolver_unpinned import (
    RULE,
    check,
)


def _ctx(tmp_path, text):
    p = tmp_path / "tk.yaml"
    p.write_text(text)
    return TektonContext.from_path(p), str(p)


class TestTKN016RemoteResolverUnpinned:
    def test_metadata(self):
        assert RULE.id == "TKN-016"
        assert RULE.severity is Severity.HIGH

    def test_git_resolver_branch_revision_fails(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: clone\n      taskRef:\n        resolver: git\n"
            "        params:\n"
            "          - {name: url, value: https://github.com/org/tasks}\n"
            "          - {name: revision, value: main}\n"
            "          - {name: pathInRepo, value: git-clone.yaml}\n"
        )
        ctx, path = _ctx(tmp_path, text)
        f = check(ctx)
        assert not f.passed
        assert f.locations and f.locations[0].path == path
        assert "git resolver" in f.description

    def test_git_resolver_commit_sha_passes(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: clone\n      taskRef:\n        resolver: git\n"
            "        params:\n"
            "          - {name: url, value: https://github.com/org/tasks}\n"
            "          - {name: revision, value: 6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        assert check(ctx).passed

    def test_bundles_resolver_without_digest_fails(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: t\n      taskRef:\n        resolver: bundles\n"
            "        params:\n"
            "          - {name: bundle, value: 'reg.example/catalog:latest'}\n"
            "          - {name: name, value: build}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        f = check(ctx)
        assert not f.passed and "bundles resolver" in f.description

    def test_bundles_resolver_with_digest_passes(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: t\n      taskRef:\n        resolver: bundles\n"
            "        params:\n"
            "          - {name: bundle, value: 'reg.example/catalog@sha256:abc123'}\n"
            "          - {name: name, value: build}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        assert check(ctx).passed

    def test_legacy_bundle_field_without_digest_fails(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: t\n      taskRef:\n"
            "        name: build\n        bundle: reg.example/catalog:v1\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        f = check(ctx)
        assert not f.passed and "bundle" in f.description

    def test_hub_resolver_latest_fails(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: TaskRun\nmetadata: {name: r}\n"
            "spec:\n  taskRef:\n    resolver: hub\n    params:\n"
            "      - {name: name, value: git-clone}\n"
            "      - {name: version, value: latest}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        f = check(ctx)
        assert not f.passed and "hub resolver" in f.description

    def test_pipelinerun_ref_checked(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: PipelineRun\nmetadata: {name: r}\n"
            "spec:\n  pipelineRef:\n    resolver: git\n    params:\n"
            "      - {name: url, value: https://github.com/org/p}\n"
            "      - {name: revision, value: release}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        f = check(ctx)
        assert not f.passed and "pipelineRef" in f.description

    def test_cluster_resolver_not_flagged(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: t\n      taskRef:\n        resolver: cluster\n"
            "        params:\n"
            "          - {name: kind, value: task}\n"
            "          - {name: name, value: build}\n"
            "          - {name: namespace, value: ci}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        assert check(ctx).passed

    def test_inline_taskspec_passes(self, tmp_path):
        text = (
            "apiVersion: tekton.dev/v1\nkind: Pipeline\nmetadata: {name: p}\n"
            "spec:\n  tasks:\n"
            "    - name: t\n      taskSpec:\n        steps:\n"
            "          - {name: s, image: alpine@sha256:abc, script: echo hi}\n"
        )
        ctx, _ = _ctx(tmp_path, text)
        assert check(ctx).passed

    def test_no_docs_passes(self, tmp_path):
        text = "apiVersion: tekton.dev/v1\nkind: ConfigMap\nmetadata: {name: c}\n"
        ctx, _ = _ctx(tmp_path, text)
        assert check(ctx).passed
