"""Drone CI provider, parses ``.drone.yml`` / ``.drone.yaml``.

    pipeline_check --pipeline drone --drone-path .drone.yml

YAML-only, no Drone API token, no CI server credentials.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.drone.base import DroneContext
from ..checks.drone.pipelines import DronePipelineChecks
from ..inventory import Component
from .base import BaseProvider


class DroneProvider(BaseProvider):
    """Drone CI provider, parses pipeline YAML."""

    NAME = "drone"

    def build_context(
        self,
        drone_path: str | None = None,
        **_: Any,
    ) -> DroneContext:
        if not drone_path:
            raise ValueError(
                "The drone provider requires --drone-path "
                "<file-or-dir> pointing at a .drone.yml file or a "
                "directory containing one."
            )
        return DroneContext.from_path(drone_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [DronePipelineChecks]

    def inventory(self, context: DroneContext) -> list[Component]:
        out: list[Component] = []
        for pipe in context.pipelines:
            data = pipe.data if isinstance(pipe.data, dict) else {}
            steps = data.get("steps") or []
            services = data.get("services") or []
            metadata: dict[str, Any] = {
                "type": data.get("type", "docker"),
                "step_count": (
                    sum(1 for s in steps if isinstance(s, dict))
                    if isinstance(steps, list) else 0
                ),
                "service_count": (
                    sum(1 for s in services if isinstance(s, dict))
                    if isinstance(services, list) else 0
                ),
            }
            name = data.get("name")
            if isinstance(name, str) and name.strip():
                metadata["name"] = name.strip()
            trigger = data.get("trigger")
            if isinstance(trigger, dict):
                # Filter to the keys most relevant to a security audit
                # (which events / branches the pipeline runs on); other
                # trigger keys (status, instance, target) are dropped
                # to keep the inventory blob small.
                for key in ("event", "branch", "ref"):
                    value = trigger.get(key)
                    if value is not None:
                        metadata[f"trigger_{key}"] = value
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
