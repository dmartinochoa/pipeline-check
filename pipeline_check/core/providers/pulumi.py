"""Pulumi IaC provider, scans Pulumi project files on disk.

    pipeline_check --pipeline pulumi --pulumi-path path/to/Pulumi.yaml

Default mode is text-only static analysis of ``Pulumi.yaml`` +
``Pulumi.<stack>.yaml`` + project source files (Python / TypeScript /
Go / C#). No Pulumi CLI required, no engine execution. Mirrors the
Terraform-HCL / CloudFormation / Helm chart-supply-chain providers.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.pulumi.base import PulumiContext
from ..checks.pulumi.pipelines import PulumiChecks
from ..inventory import Component
from .base import BaseProvider


class PulumiProvider(BaseProvider):
    """Pulumi provider, parses Pulumi.yaml + Pulumi.<stack>.yaml."""

    NAME = "pulumi"

    def build_context(
        self,
        pulumi_path: str | None = None,
        **_: Any,
    ) -> PulumiContext:
        if not pulumi_path:
            raise ValueError(
                "The pulumi provider requires --pulumi-path "
                "<file-or-dir> pointing at a Pulumi.yaml or a "
                "directory containing one."
            )
        return PulumiContext.from_path(pulumi_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [PulumiChecks]

    def inventory(self, context: PulumiContext) -> list[Component]:
        out: list[Component] = []
        for project in context.projects:
            metadata: dict[str, Any] = {
                "kind": "Pulumi.yaml",
                "name": project.name or None,
                "runtime": project.runtime or None,
                "backend_url": project.backend_url,
            }
            out.append(Component(
                provider=self.NAME, type="Pulumi.yaml",
                identifier=project.path, source=project.path,
                metadata=metadata,
            ))
        for stack in context.stacks:
            metadata = {
                "kind": "Pulumi.<stack>.yaml",
                "stack": stack.stack_name,
                "secrets_provider": stack.secrets_provider,
                "encryption_salt": bool(stack.encryption_salt),
                "config_keys": len(stack.config),
            }
            out.append(Component(
                provider=self.NAME, type="Pulumi.stack.yaml",
                identifier=stack.path, source=stack.path,
                metadata=metadata,
            ))
        for source in context.sources:
            out.append(Component(
                provider=self.NAME, type="pulumi-source",
                identifier=source.path, source=source.path,
                metadata={
                    "kind": "source",
                    "runtime": source.runtime,
                },
            ))
        return out
