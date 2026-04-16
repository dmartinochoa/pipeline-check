"""CircleCI provider — scans ``.circleci/config.yml``.

    pipeline_check --pipeline circleci --circleci-path .circleci/config.yml

Only YAML parsing is required — no network calls, no CircleCI API token.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.circleci.base import CircleCIContext
from ..checks.circleci.pipelines import CircleCIPipelineChecks
from .base import BaseProvider


class CircleCIProvider(BaseProvider):
    """CircleCI provider — parses config YAML from disk."""

    NAME = "circleci"

    def build_context(self, circleci_path: str | None = None, **_: Any) -> CircleCIContext:
        if not circleci_path:
            raise ValueError(
                "The circleci provider requires --circleci-path <file-or-dir> "
                "pointing at a .circleci/config.yml file or a directory "
                "containing one."
            )
        return CircleCIContext.from_path(circleci_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [CircleCIPipelineChecks]
