"""Model-registry provider, scans Ollama ``Modelfile`` declarations on disk.

    pipeline_check --pipeline modelfile --modelfile-path path/to/Modelfile

No model pull, no Ollama daemon, text-only static analysis of the ``FROM``
/ ``ADAPTER`` model references a Modelfile declares. The static,
declaration-side complement to the CI-script AI rules (GHA-120/121/122,
GL-045..049).
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.modelfile.base import ModelfileContext
from ..checks.modelfile.checks import ModelfileChecks
from ..inventory import Component
from .base import BaseProvider


class ModelfileProvider(BaseProvider):
    """Model-registry provider, parses Ollama Modelfile documents."""

    NAME = "modelfile"

    def build_context(
        self,
        modelfile_path: str | None = None,
        **_: Any,
    ) -> ModelfileContext:
        # Default to cwd: the canonical layout is a repo root holding a
        # ``Modelfile``. A missing flag therefore scans the working tree
        # rather than raising (no traceback on a bare ``--pipeline modelfile``).
        return ModelfileContext.from_path(modelfile_path or ".")

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [ModelfileChecks]

    def inventory(self, context: ModelfileContext) -> list[Component]:
        out: list[Component] = []
        for mc in context.model_configs:
            out.append(Component(
                provider=self.NAME,
                type="model_config",
                identifier=mc.path,
                source=mc.path,
                metadata={
                    "model_type": str(mc.data.get("model_type", "")),
                    "has_auto_map": "auto_map" in mc.data,
                },
            ))
        for mf in context.modelfiles:
            from_count = sum(
                1 for d in mf.directives if d.directive == "FROM"
            )
            adapter_count = sum(
                1 for d in mf.directives if d.directive == "ADAPTER"
            )
            out.append(Component(
                provider=self.NAME,
                type="modelfile",
                identifier=mf.path,
                source=mf.path,
                metadata={
                    "directive_count": len(mf.directives),
                    "base_models": from_count,
                    "adapters": adapter_count,
                },
            ))
        return out
