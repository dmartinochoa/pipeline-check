"""Google Cloud Build provider — scans ``cloudbuild.yaml`` on disk.

    pipeline_check --pipeline cloudbuild --cloudbuild-path path/to/cloudbuild.yaml

Only YAML parsing is required — no Cloud Build API token, no Google
credentials. Mirrors the shape of the GitHub/GitLab providers for
consistency.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.cloudbuild.base import CloudBuildContext
from ..checks.cloudbuild.pipelines import CloudBuildPipelineChecks
from ..inventory import Component
from .base import BaseProvider


class CloudBuildProvider(BaseProvider):
    """Cloud Build provider — parses ``cloudbuild.yaml`` documents."""

    NAME = "cloudbuild"

    def build_context(
        self,
        cloudbuild_path: str | None = None,
        **_: Any,
    ) -> CloudBuildContext:
        if not cloudbuild_path:
            raise ValueError(
                "The cloudbuild provider requires --cloudbuild-path "
                "<file-or-dir> pointing at a cloudbuild.yaml file or a "
                "directory containing one."
            )
        return CloudBuildContext.from_path(cloudbuild_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [CloudBuildPipelineChecks]

    def inventory(self, context: CloudBuildContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            steps = data.get("steps") or []
            step_count = len(steps) if isinstance(steps, list) else 0
            sa = data.get("serviceAccount")
            metadata: dict = {"step_count": step_count}
            if isinstance(sa, str) and sa.strip():
                metadata["service_account"] = sa
            options = data.get("options") or {}
            if isinstance(options, dict) and options.get("pool"):
                pool = options["pool"]
                if isinstance(pool, dict) and pool.get("name"):
                    metadata["worker_pool"] = pool["name"]
            out.append(Component(
                provider=self.NAME,
                type="pipeline",
                identifier=pipe.path,
                source=pipe.path,
                metadata=metadata,
            ))
        return out
