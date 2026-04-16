"""Shared helpers for Azure DevOps pipeline tests."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.azure.base import AzureContext, Pipeline
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks


def azure_ctx(yaml_text: str, path: str = "azure-pipelines.yml") -> AzureContext:
    """Parse a YAML snippet into an AzureContext with a single pipeline doc."""
    data = yaml.safe_load(textwrap.dedent(yaml_text))
    return AzureContext([Pipeline(path=path, data=data)])


def run_check(yaml_text: str, check_id: str):
    """Run every Azure check and return the Finding with the given check_id."""
    return next(
        f for f in AzurePipelineChecks(azure_ctx(yaml_text)).run()
        if f.check_id == check_id
    )
