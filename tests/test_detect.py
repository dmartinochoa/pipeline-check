"""Tests for provider auto-detection (core/detect.py)."""
from __future__ import annotations

from pipeline_check.core.detect import (
    detect_all_pipelines_from_cwd,
    detect_pipeline_from_cwd,
)


def test_empty_dir_detects_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert detect_pipeline_from_cwd() is None
    assert detect_all_pipelines_from_cwd() == []


def test_single_provider(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
    assert detect_pipeline_from_cwd() == "gitlab"
    assert detect_all_pipelines_from_cwd() == ["gitlab"]


def test_github_workflows_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert detect_pipeline_from_cwd() == "github"


def test_first_match_wins_for_single(tmp_path, monkeypatch):
    # github sorts before dockerfile in the table, so it wins the single pick.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    assert detect_pipeline_from_cwd() == "github"
    assert detect_all_pipelines_from_cwd() == ["github", "dockerfile"]


def test_helm_drops_kubernetes_in_multi(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Chart.yaml").write_text("name: x\n")
    (tmp_path / "manifests").mkdir()
    detected = detect_all_pipelines_from_cwd()
    assert "helm" in detected
    assert "kubernetes" not in detected
