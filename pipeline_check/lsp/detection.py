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

from pathlib import PurePosixPath


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
    # POSIX. Always replace backslashes (not just ``os.sep``): an LSP
    # client running on Windows can hand a backslashed path to a
    # Linux-side scan, and the test suite asserts this works on both
    # platforms. ``PurePosixPath`` lets us compare against
    # forward-slash idioms (``.github/workflows/...``) regardless of
    # the source OS.
    posix = PurePosixPath(path.replace("\\", "/"))
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

    return None
