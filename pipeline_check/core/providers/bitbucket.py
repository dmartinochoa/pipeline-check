"""Bitbucket Pipelines provider — scans ``bitbucket-pipelines.yml``.

    pipeline_check --pipeline bitbucket --bitbucket-path path/to/bitbucket-pipelines.yml

Only YAML parsing is required — no network calls, no Bitbucket API token.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.bitbucket.base import BitbucketContext
from ..checks.bitbucket.pipelines import BitbucketPipelineChecks
from ..inventory import Component
from .base import BaseProvider


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

    def inventory(self, context: BitbucketContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            top = data.get("pipelines") or {}
            categories = sorted(k for k in top.keys() if isinstance(k, str))
            out.append(Component(
                provider=self.NAME,
                type="pipeline",
                identifier=pipe.path,
                source=pipe.path,
                metadata={"categories": categories} if categories else {},
            ))
        return out
