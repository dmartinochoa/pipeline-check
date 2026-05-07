"""Buildkite provider — scans ``.buildkite/pipeline.yml`` on disk.

    pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml

Only YAML parsing is required — no Buildkite API token, no agent
credentials.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.buildkite.base import BuildkiteContext
from ..checks.buildkite.pipelines import BuildkitePipelineChecks
from ..inventory import Component
from .base import BaseProvider


class BuildkiteProvider(BaseProvider):
    """Buildkite provider — parses pipeline.yml documents."""

    NAME = "buildkite"

    def build_context(
        self,
        buildkite_path: str | None = None,
        **_: Any,
    ) -> BuildkiteContext:
        if not buildkite_path:
            raise ValueError(
                "The buildkite provider requires --buildkite-path "
                "<file-or-dir> pointing at a pipeline.yml file or a "
                "directory containing one."
            )
        return BuildkiteContext.from_path(buildkite_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [BuildkitePipelineChecks]

    def inventory(self, context: BuildkiteContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            steps = data.get("steps") or []
            step_count = (
                sum(
                    1 for s in steps
                    if isinstance(s, dict)
                    and not any(
                        k in s for k in ("wait", "block", "input", "trigger")
                    )
                )
                if isinstance(steps, list)
                else 0
            )
            metadata: dict[str, Any] = {"step_count": step_count}
            agents = data.get("agents")
            if isinstance(agents, dict) and agents.get("queue"):
                metadata["queue"] = agents["queue"]
            out.append(Component(
                provider=self.NAME,
                type="pipeline",
                identifier=pipe.path,
                source=pipe.path,
                metadata=metadata,
            ))
        return out
