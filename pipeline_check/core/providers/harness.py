"""Harness CI/CD provider, parses Harness pipeline YAML.

    pipeline_check --pipeline harness --harness-path .harness/

YAML-only, no Harness API token, no platform credentials.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.harness.base import HarnessContext
from ..checks.harness.pipelines import HarnessPipelineChecks
from ..inventory import Component
from .base import BaseProvider


class HarnessProvider(BaseProvider):
    """Harness CI/CD provider, parses pipeline YAML."""

    NAME = "harness"

    def build_context(
        self,
        harness_path: str | None = None,
        **_: Any,
    ) -> HarnessContext:
        if not harness_path:
            raise ValueError(
                "The harness provider requires --harness-path "
                "<file-or-dir> pointing at a Harness pipeline YAML file or "
                "a directory containing one (for example a .harness/ "
                "folder)."
            )
        return HarnessContext.from_path(harness_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [HarnessPipelineChecks]

    def inventory(self, context: HarnessContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            stages = data.get("stages") or []
            metadata: dict[str, Any] = {
                "stage_count": (
                    sum(1 for s in stages if isinstance(s, dict))
                    if isinstance(stages, list) else 0
                ),
            }
            name = data.get("name")
            if isinstance(name, str) and name.strip():
                metadata["name"] = name.strip()
            identifier = (
                f"{pipe.path}#{pipe.doc_index}"
                if pipe.doc_index else pipe.path
            )
            out.append(Component(
                provider=self.NAME,
                type="pipeline",
                identifier=identifier,
                source=pipe.path,
                metadata=metadata,
            ))
        return out
