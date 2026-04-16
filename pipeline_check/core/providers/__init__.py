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

from .base import BaseProvider
from .aws import AWSProvider
from .azure import AzureProvider
from .bitbucket import BitbucketProvider
from .github import GitHubProvider
from .gitlab import GitLabProvider
from .jenkins import JenkinsProvider
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
register(GitHubProvider())
register(GitLabProvider())
register(BitbucketProvider())
register(AzureProvider())
register(JenkinsProvider())
