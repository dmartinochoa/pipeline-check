"""Per-document provider detection."""
from __future__ import annotations

import pytest

from pipeline_check.lsp.detection import detect_provider


@pytest.mark.parametrize(
    "path,expected",
    [
        # github
        (".github/workflows/release.yml", "github"),
        (".github/workflows/build.yaml", "github"),
        ("foo/.github/workflows/test.yml", "github"),
        # gitlab
        (".gitlab-ci.yml", "gitlab"),
        ("nested/.gitlab-ci.yaml", "gitlab"),
        # circleci
        (".circleci/config.yml", "circleci"),
        ("repo/.circleci/config.yaml", "circleci"),
        # azure
        ("azure-pipelines.yml", "azure"),
        ("azure-pipelines.yaml", "azure"),
        # bitbucket
        ("bitbucket-pipelines.yml", "bitbucket"),
        # buildkite
        (".buildkite/pipeline.yml", "buildkite"),
        # cloudbuild
        ("cloudbuild.yml", "cloudbuild"),
        ("cloudbuild.yaml", "cloudbuild"),
        # drone
        (".drone.yml", "drone"),
        # jenkins
        ("Jenkinsfile", "jenkins"),
        ("subdir/Jenkinsfile", "jenkins"),
        # dockerfile shapes
        ("Dockerfile", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("Dockerfile.prod", "dockerfile"),
        ("api.Dockerfile", "dockerfile"),
        # negatives
        ("README.md", None),
        ("docs/index.md", None),
        ("random.yml", None),
        ("", None),
    ],
)
def test_detect_provider(path: str, expected: str | None) -> None:
    assert detect_provider(path) == expected


def test_detect_provider_case_insensitive_jenkinsfile() -> None:
    # Jenkinsfile is the canonical capitalization; case-folded match
    # keeps the LSP resilient to operator typos.
    assert detect_provider("jenkinsfile") == "jenkins"
    assert detect_provider("JENKINSFILE") == "jenkins"


def test_detect_provider_windows_separators() -> None:
    # Windows path separators should normalize to forward slashes
    # before the part-match runs.
    assert detect_provider(r".github\workflows\release.yml") == "github"
    assert detect_provider(r".circleci\config.yml") == "circleci"
