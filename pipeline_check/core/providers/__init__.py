"""Provider registry.

Built-in providers are registered at the bottom of this module.
Third-party providers can register themselves before creating a Scanner:

    from pipeline_check.core.providers import register
    from mypkg.providers.github import GitHubProvider
    register(GitHubProvider())

After registration the new provider is available via ``--pipeline github``
without any changes to Scanner or the CLI.
"""
from __future__ import annotations

from .argo import ArgoProvider
from .argocd import ArgoCDProvider
from .aws import AWSProvider
from .azure import AzureProvider
from .azure_cloud import AzureCloudProvider
from .base import BaseProvider
from .bitbucket import BitbucketProvider
from .buildkite import BuildkiteProvider
from .circleci import CircleCIProvider
from .cloudbuild import CloudBuildProvider
from .cloudformation import CloudFormationProvider
from .dockerfile import DockerfileProvider
from .drone import DroneProvider
from .gcp import GCPProvider
from .github import GitHubProvider
from .gitlab import GitLabProvider
from .helm import HelmProvider
from .jenkins import JenkinsProvider
from .kubernetes import KubernetesProvider
from .maven import MavenProvider
from .npm import NpmProvider
from .nuget import NuGetProvider
from .oci import OCIProvider
from .pypi import PypiProvider
from .scm import SCMProvider
from .tekton import TektonProvider
from .terraform import TerraformProvider

_REGISTRY: dict[str, BaseProvider] = {}


def register(provider: BaseProvider) -> None:
    """Add *provider* to the registry, keyed by ``provider.NAME``."""
    if not provider.NAME:
        raise ValueError("BaseProvider.NAME must be a non-empty string.")
    _REGISTRY[provider.NAME.lower()] = provider


def get(name: str) -> BaseProvider | None:
    """Return the provider registered under *name*, or ``None`` if unknown."""
    return _REGISTRY.get(name.lower())


def available() -> list[str]:
    """Return a sorted list of all registered provider names."""
    return sorted(_REGISTRY.keys())


# ── Register built-in providers ───────────────────────────────────────────────
register(AWSProvider())
register(TerraformProvider())
register(CloudFormationProvider())
register(GitHubProvider())
register(GitLabProvider())
register(BitbucketProvider())
register(AzureProvider())
register(AzureCloudProvider())
register(JenkinsProvider())
register(CircleCIProvider())
register(CloudBuildProvider())
register(BuildkiteProvider())
register(TektonProvider())
register(ArgoProvider())
register(ArgoCDProvider())
register(DockerfileProvider())
register(KubernetesProvider())
register(HelmProvider())
register(OCIProvider())
register(DroneProvider())
register(GCPProvider())
register(SCMProvider())
register(NpmProvider())
register(PypiProvider())
register(MavenProvider())
register(NuGetProvider())
