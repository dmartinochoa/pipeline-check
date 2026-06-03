"""Developer-environment provider, scans editor / agent / container configs.

    pipeline_check --pipeline devenv --devenv-path .

Parses the config files that auto-execute on repo open (``.vscode/
tasks.json``, ``.devcontainer/devcontainer.json``,
``.claude/settings.json``). Text-only JSON(C) parsing, no tokens, no
network. Distinct from the CI-pipeline providers: this surface is the
developer's machine on checkout, not the build runner.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.devenv.base import DevEnvContext
from ..checks.devenv.checks import DevEnvChecks
from ..inventory import Component
from .base import BaseProvider


class DevEnvProvider(BaseProvider):
    """Developer-environment provider, parses editor / agent / container config."""

    NAME = "devenv"

    def build_context(
        self,
        devenv_path: str | None = None,
        **_: Any,
    ) -> DevEnvContext:
        # Default to cwd: the canonical layout is a repo root that holds
        # ``.vscode/`` / ``.devcontainer/`` / ``.claude/`` directories.
        return DevEnvContext.from_path(devenv_path or ".")

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [DevEnvChecks]

    def inventory(self, context: DevEnvContext) -> list[Component]:
        out: list[Component] = []
        for wf in context.files:
            out.append(Component(
                provider=self.NAME,
                type=wf.kind,
                identifier=wf.path,
                source=wf.path,
                metadata={"kind": wf.kind},
            ))
        return out
