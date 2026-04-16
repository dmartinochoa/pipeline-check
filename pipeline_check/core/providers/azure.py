"""Azure DevOps Pipelines provider — scans ``azure-pipelines.yml``.

    pipeline_check --pipeline azure --azure-path azure-pipelines.yml

Only YAML parsing is required — no network calls, no ADO PAT.
"""
from __future__ import annotations

from typing import Any

from ..checks.azure.base import AzureContext
from ..checks.azure.pipelines import AzurePipelineChecks
from ..checks.base import BaseCheck
from .base import BaseProvider


class AzureProvider(BaseProvider):
    """Azure DevOps Pipelines provider — parses pipeline YAML from disk."""

    NAME = "azure"

    def build_context(self, azure_path: str | None = None, **_: Any) -> AzureContext:
        if not azure_path:
            raise ValueError(
                "The azure provider requires --azure-path <file-or-dir> "
                "pointing at an azure-pipelines.yml file or a directory "
                "containing one."
            )
        return AzureContext.from_path(azure_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [AzurePipelineChecks]
