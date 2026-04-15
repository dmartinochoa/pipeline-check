"""Bitbucket Pipelines provider — scans ``bitbucket-pipelines.yml``.

    pipeline_check --pipeline bitbucket --bitbucket-path path/to/bitbucket-pipelines.yml

Only YAML parsing is required — no network calls, no Bitbucket API token.
"""
from __future__ import annotations

from typing import Any

from .base import BaseProvider
from ..checks.base import BaseCheck
from ..checks.bitbucket.base import BitbucketContext
from ..checks.bitbucket.pipelines import BitbucketPipelineChecks


class BitbucketProvider(BaseProvider):
    """Bitbucket Pipelines provider — parses pipeline YAML from disk."""

    NAME = "bitbucket"

    def build_context(self, bitbucket_path: str | None = None, **_: Any) -> BitbucketContext:
        if not bitbucket_path:
            raise ValueError(
                "The bitbucket provider requires --bitbucket-path <file-or-dir> "
                "pointing at a bitbucket-pipelines.yml file or a directory "
                "containing one."
            )
        return BitbucketContext.from_path(bitbucket_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [BitbucketPipelineChecks]
