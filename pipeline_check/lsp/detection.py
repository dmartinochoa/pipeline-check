"""Per-document provider detection.

The CLI's :func:`pipeline_check.cli._detect_pipeline_from_cwd` walks a
working directory; the LSP needs the same decision applied to a single
file's path (the open / changed document). Returns one of the
single-file provider names — multi-file / context-heavy providers
(``kubernetes``, ``helm``, ``terraform``, ``aws``, ``cloudformation``,
``scm``) are intentionally absent from this initial pilot because their
contexts span more than one document. A follow-up commit can widen the
set.
"""
from __future__ import annotations

import os
from pathlib import PurePosixPath

# (provider, predicate-on-PurePosixPath) entries. First match wins.
# Order mirrors :data:`pipeline_check.cli._PROVIDER_DETECT_FILES`
# where applicable so the LSP and the CLI agree on which provider
# owns a given filename.
_DETECTORS: tuple[tuple[str, str], ...] = (
    ("github", "github-workflows-yaml"),
    ("gitlab", "gitlab-ci-yaml"),
    ("circleci", "circleci-config-yaml"),
    ("azure", "azure-pipelines-yaml"),
    ("bitbucket", "bitbucket-pipelines-yaml"),
    ("buildkite", "buildkite-pipeline-yaml"),
    ("cloudbuild", "cloudbuild-yaml"),
    ("drone", "drone-yaml"),
    ("jenkins", "jenkinsfile"),
    ("dockerfile", "dockerfile"),
)


def detect_provider(path: str) -> str | None:
    """Return the provider name that owns *path*, or ``None``.

    Path is treated case-insensitively on case-insensitive filesystems
    (Windows / macOS); Linux callers get exact matching. URI schemes
    are not handled here — callers feed the filesystem path extracted
    from the ``file://`` URI.
    """
    if not path:
        return None
    # Normalize separators so the same rule files match on Windows and
    # POSIX. ``PurePosixPath`` lets us compare against forward-slash
    # idioms (``.github/workflows/...``) regardless of source OS.
    posix = PurePosixPath(path.replace(os.sep, "/"))
    parts = tuple(p.lower() for p in posix.parts)
    name = posix.name
    name_lc = name.lower()
    suffix_lc = posix.suffix.lower()

    # GitHub Actions: any *.yml / *.yaml file under .github/workflows
    if suffix_lc in (".yml", ".yaml"):
        if any(
            parts[i:i + 2] == (".github", "workflows")
            for i in range(len(parts) - 1)
        ):
            return "github"

    if name_lc in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return "gitlab"

    if posix.parent.name.lower() == ".circleci" and name_lc in (
        "config.yml", "config.yaml",
    ):
        return "circleci"

    if name_lc in ("azure-pipelines.yml", "azure-pipelines.yaml"):
        return "azure"

    if name_lc in ("bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"):
        return "bitbucket"

    if posix.parent.name.lower() == ".buildkite" and name_lc in (
        "pipeline.yml", "pipeline.yaml",
    ):
        return "buildkite"

    if name_lc in ("cloudbuild.yml", "cloudbuild.yaml"):
        return "cloudbuild"

    if name_lc in (".drone.yml", ".drone.yaml"):
        return "drone"

    if name_lc == "jenkinsfile":
        return "jenkins"

    # Dockerfile shapes: ``Dockerfile``, ``Containerfile``,
    # ``Dockerfile.<suffix>``, ``*.Dockerfile``. Matches the loader
    # convention in :class:`pipeline_check.core.checks.dockerfile.base`.
    if name_lc in ("dockerfile", "containerfile"):
        return "dockerfile"
    if name_lc.startswith("dockerfile."):
        return "dockerfile"
    if name_lc.endswith(".dockerfile"):
        return "dockerfile"

    # Silence the unused-name warning on _DETECTORS; the table is kept
    # for documentation symmetry with the CLI's _PROVIDER_DETECT_FILES.
    _ = _DETECTORS
    return None
