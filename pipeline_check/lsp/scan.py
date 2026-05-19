"""Per-document scan dispatch.

Given a filesystem path and a detected provider name, builds the
appropriate single-document context and runs every check class the
provider registers. Returns the resulting ``list[Finding]``.

Multi-file providers (``kubernetes``, ``helm``, ``terraform``,
``aws``, ``cloudformation``, ``scm``) are intentionally absent from
this initial pilot: their contexts span more than one document and
would need different plumbing (workspace scans, ``helm template``
shell-outs, plan JSON inputs). A follow-up commit can widen the set
once we settle on per-provider strategies.

The dispatch table maps provider name → callable that takes the
document path and returns a context. Each provider's check-class
registry runs against that context exactly the way the CLI runs it,
so editor diagnostics and CLI findings agree.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.checks.base import Finding
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.checks.buildkite.base import BuildkiteContext
from pipeline_check.core.checks.circleci.base import CircleCIContext
from pipeline_check.core.checks.cloudbuild.base import CloudBuildContext
from pipeline_check.core.checks.dockerfile.base import DockerfileContext
from pipeline_check.core.checks.drone.base import DroneContext
from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.providers.azure import AzureProvider
from pipeline_check.core.providers.base import BaseProvider
from pipeline_check.core.providers.bitbucket import BitbucketProvider
from pipeline_check.core.providers.buildkite import BuildkiteProvider
from pipeline_check.core.providers.circleci import CircleCIProvider
from pipeline_check.core.providers.cloudbuild import CloudBuildProvider
from pipeline_check.core.providers.dockerfile import DockerfileProvider
from pipeline_check.core.providers.drone import DroneProvider
from pipeline_check.core.providers.github import GitHubProvider
from pipeline_check.core.providers.gitlab import GitLabProvider
from pipeline_check.core.providers.jenkins import JenkinsProvider


def _build_github_ctx(path: str) -> GitHubContext:
    # GitHubContext.from_path accepts both a directory and a single
    # workflow file. Single-file mode is what the LSP wants.
    return GitHubContext.from_path(path)


def _build_gitlab_ctx(path: str) -> GitLabContext:
    return GitLabContext.from_path(path)


def _build_azure_ctx(path: str) -> AzureContext:
    return AzureContext.from_path(path)


def _build_bitbucket_ctx(path: str) -> BitbucketContext:
    return BitbucketContext.from_path(path)


def _build_circleci_ctx(path: str) -> CircleCIContext:
    return CircleCIContext.from_path(path)


def _build_cloudbuild_ctx(path: str) -> CloudBuildContext:
    return CloudBuildContext.from_path(path)


def _build_buildkite_ctx(path: str) -> BuildkiteContext:
    return BuildkiteContext.from_path(path)


def _build_drone_ctx(path: str) -> DroneContext:
    return DroneContext.from_path(path)


def _build_jenkins_ctx(path: str) -> JenkinsContext:
    return JenkinsContext.from_path(path)


def _build_dockerfile_ctx(path: str) -> DockerfileContext:
    return DockerfileContext.from_path(path)


# (context-builder, provider-class) per provider name. The provider
# class is the canonical source of the check-class registry so the
# LSP runs exactly the rules the CLI runs.
_DISPATCH: dict[str, tuple[Callable[[str], Any], type[BaseProvider]]] = {
    "github":     (_build_github_ctx,     GitHubProvider),
    "gitlab":     (_build_gitlab_ctx,     GitLabProvider),
    "azure":      (_build_azure_ctx,      AzureProvider),
    "bitbucket":  (_build_bitbucket_ctx,  BitbucketProvider),
    "circleci":   (_build_circleci_ctx,   CircleCIProvider),
    "cloudbuild": (_build_cloudbuild_ctx, CloudBuildProvider),
    "buildkite":  (_build_buildkite_ctx,  BuildkiteProvider),
    "drone":      (_build_drone_ctx,      DroneProvider),
    "jenkins":    (_build_jenkins_ctx,    JenkinsProvider),
    "dockerfile": (_build_dockerfile_ctx, DockerfileProvider),
}


def supported_providers() -> frozenset[str]:
    """Return every provider name the LSP currently scans."""
    return frozenset(_DISPATCH)


def scan_document(provider: str, path: str) -> list[Finding]:
    """Run *provider*'s checks against the single file at *path*.

    Raises :class:`KeyError` when the provider is not in the dispatch
    table; callers should pre-filter through :func:`detect_provider`.
    Returns the full ``list[Finding]`` — failing and passing — so the
    caller (the LSP server) can decide which ones to translate. Any
    exception raised by the context builder or a check class bubbles
    up; the server logs and swallows.
    """
    builder, provider_cls = _DISPATCH[provider]
    ctx = builder(path)
    findings: list[Finding] = []
    provider_instance = provider_cls()
    for check_cls in provider_instance.check_classes:
        check = check_cls(ctx)
        findings.extend(check.run())
    return findings
