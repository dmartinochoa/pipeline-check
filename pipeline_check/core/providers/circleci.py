"""CircleCI provider — scans ``.circleci/config.yml``.

    pipeline_check --pipeline circleci --circleci-path .circleci/config.yml

Only YAML parsing is required — no network calls, no CircleCI API token.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.circleci.base import CircleCIContext
from ..checks.circleci.pipelines import CircleCIPipelineChecks
from ..inventory import Component
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

    def inventory(self, context: CircleCIContext) -> list[Component]:
        out: list[Component] = []
        # CircleCIContext exposes the parsed config(s). Attribute
        # naming varies between forks of the loader, so accept either
        # ``.pipelines`` or ``.configs``.
        configs = getattr(context, "pipelines", None) or getattr(context, "configs", [])
        for pipe in configs:
            data = getattr(pipe, "data", None) or {}
            if not isinstance(data, dict):
                data = {}
            path = getattr(pipe, "path", "")
            jobs = sorted((data.get("jobs") or {}).keys()) if isinstance(data.get("jobs"), dict) else []
            workflows = sorted((data.get("workflows") or {}).keys()) if isinstance(data.get("workflows"), dict) else []
            # ``version`` appears as a keyword under ``workflows`` for CircleCI 2.1+
            workflows = [w for w in workflows if w != "version"]
            metadata: dict = {}
            if jobs:
                metadata["jobs"] = jobs
            if workflows:
                metadata["workflows"] = workflows
            out.append(Component(
                provider=self.NAME,
                type="config",
                identifier=path,
                source=path,
                metadata=metadata,
            ))
        return out
