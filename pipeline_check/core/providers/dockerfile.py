"""Dockerfile provider, scans Dockerfile / Containerfile on disk.

    pipeline_check --pipeline dockerfile --dockerfile-path path/to/Dockerfile

No registry pull, no image build, no daemon access, text-only static
analysis. Mirrors the shape of the YAML CI providers (GitHub, GitLab,
Bitbucket, Cloud Build).
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.dockerfile.base import DockerfileContext, from_refs
from ..checks.dockerfile.pipelines import DockerfileChecks
from ..inventory import Component
from ..sbom import BuildDependency, make_docker_purl, parse_docker_ref
from .base import BaseProvider


class DockerfileProvider(BaseProvider):
    """Dockerfile provider, parses Dockerfile / Containerfile documents."""

    NAME = "dockerfile"

    def build_context(
        self,
        dockerfile_path: str | None = None,
        **_: Any,
    ) -> DockerfileContext:
        if not dockerfile_path:
            raise ValueError(
                "The dockerfile provider requires --dockerfile-path "
                "<file-or-dir> pointing at a Dockerfile or a directory "
                "containing one."
            )
        return DockerfileContext.from_path(dockerfile_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [DockerfileChecks]

    def build_dependencies(
        self, context: DockerfileContext,
    ) -> list[BuildDependency]:
        deps: list[BuildDependency] = []
        for df in context.dockerfiles:
            for _line_no, ref_str in from_refs(df):
                if ref_str.lower() == "scratch":
                    continue
                image, tag, digest = parse_docker_ref(ref_str)
                deps.append(BuildDependency(
                    name=image,
                    version=tag or digest or "latest",
                    dep_type="container",
                    purl=make_docker_purl(image, tag, digest),
                    provider=self.NAME,
                    source=df.path,
                    pinned=bool(digest),
                    digest=digest,
                ))
        return deps

    def inventory(self, context: DockerfileContext) -> list[Component]:
        out: list[Component] = []
        for df in context.dockerfiles:
            from_count = sum(1 for ins in df.instructions if ins.directive == "FROM")
            run_count = sum(1 for ins in df.instructions if ins.directive == "RUN")
            metadata: dict[str, Any] = {
                "instruction_count": len(df.instructions),
                "stages": from_count,
                "run_steps": run_count,
            }
            out.append(Component(
                provider=self.NAME,
                type="dockerfile",
                identifier=df.path,
                source=df.path,
                metadata=metadata,
            ))
        return out
