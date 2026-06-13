"""Provider registry.

Built-in providers are registered lazily: the registry knows every
built-in's name up front, but a provider module (and its check tree) is
only imported the first time that provider is requested via ``get()``.
This keeps CLI startup cheap. Scanning a GitHub repo no longer imports
the AWS provider's ``botocore`` dependency, and ``--help`` imports no
provider at all.

Third-party providers can still register an instance eagerly before
creating a Scanner:

    from pipeline_check.core.providers import register
    from mypkg.providers.github import GitHubProvider
    register(GitHubProvider())

After registration the new provider is available via ``--pipeline github``
without any changes to Scanner or the CLI.
"""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import BaseProvider

#: Built-in provider name -> class name. The module is the name itself
#: (e.g. ``aws`` lives in ``aws.py``), imported lazily on first use so an
#: unrelated scan doesn't pay for every provider's check tree at import.
_BUILTINS: dict[str, str] = {
    "argo": "ArgoProvider",
    "argocd": "ArgoCDProvider",
    "aws": "AWSProvider",
    "azure": "AzureProvider",
    "azure_cloud": "AzureCloudProvider",
    "bitbucket": "BitbucketProvider",
    "buildkite": "BuildkiteProvider",
    "cargo": "CargoProvider",
    "circleci": "CircleCIProvider",
    "cloudbuild": "CloudBuildProvider",
    "cloudformation": "CloudFormationProvider",
    "composer": "ComposerProvider",
    "devenv": "DevEnvProvider",
    "dockerfile": "DockerfileProvider",
    "drone": "DroneProvider",
    "harness": "HarnessProvider",
    "gcp": "GCPProvider",
    "gitea": "GiteaProvider",
    "github": "GitHubProvider",
    "gitlab": "GitLabProvider",
    "gitlab_group": "GitLabGroupProvider",
    "gitlab_runs": "GitLabRunsProvider",
    "gomod": "GoModProvider",
    "helm": "HelmProvider",
    "jenkins": "JenkinsProvider",
    "kubernetes": "KubernetesProvider",
    "maven": "MavenProvider",
    "modelfile": "ModelfileProvider",
    "npm": "NpmProvider",
    "nuget": "NuGetProvider",
    "oci": "OCIProvider",
    "pulumi": "PulumiProvider",
    "pypi": "PypiProvider",
    "rubygems": "RubyGemsProvider",
    "runs": "RunsProvider",
    "scm": "SCMProvider",
    "scm_org": "SCMOrgProvider",
    "tekton": "TektonProvider",
    "terraform": "TerraformProvider",
}

#: Eagerly-registered provider instances: third-party registrations, plus
#: built-ins already materialized by a prior ``get()``. Checked before
#: ``_BUILTINS`` so a third-party provider can override a built-in name.
_REGISTRY: dict[str, BaseProvider] = {}


def register(provider: BaseProvider) -> None:
    """Add *provider* to the registry, keyed by ``provider.NAME``."""
    if not provider.NAME:
        raise ValueError("BaseProvider.NAME must be a non-empty string.")
    _REGISTRY[provider.NAME.lower()] = provider


def _materialize(name: str) -> BaseProvider | None:
    """Import and instantiate the built-in provider for *name*, caching it.

    Returns ``None`` when *name* isn't a known built-in.
    """
    cls_name = _BUILTINS.get(name)
    if cls_name is None:
        return None
    module = importlib.import_module(f".{name}", __name__)
    provider: BaseProvider = getattr(module, cls_name)()
    _REGISTRY[name] = provider
    return provider


def get(name: str) -> BaseProvider | None:
    """Return the provider registered under *name*, or ``None`` if unknown."""
    key = name.lower()
    provider = _REGISTRY.get(key)
    if provider is not None:
        return provider
    return _materialize(key)


def available() -> list[str]:
    """Return a sorted list of all registered provider names."""
    return sorted(_REGISTRY.keys() | _BUILTINS.keys())
