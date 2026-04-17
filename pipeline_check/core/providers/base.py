"""Abstract base for pipeline provider adapters.

A provider is responsible for two things:
  1. Building the API context (credentials, client, etc.) for its platform.
  2. Declaring the ordered list of check classes to run against that platform.

To add a new provider
---------------------
1. Create ``pipeline_check/core/providers/<provider>.py`` subclassing BaseProvider.
2. Set NAME, implement build_context() and check_classes.
3. Call ``register(<YourProvider>())`` in ``pipeline_check/core/providers/__init__.py``.

The Scanner and CLI will pick it up automatically — no other files need editing.
"""
from __future__ import annotations

import abc
from typing import Any

from ..checks.base import BaseCheck
from ..inventory import Component


class BaseProvider(abc.ABC):
    """Adapter that binds a CI/CD platform to its check classes."""

    #: Canonical lower-case name matched against ``--pipeline`` (e.g. ``"aws"``).
    NAME: str = ""

    @abc.abstractmethod
    def build_context(self, **kwargs: Any) -> Any:
        """Return the provider-specific context object.

        The returned value is passed as the first positional argument to every
        check class constructor (``BaseCheck.__init__(context, ...)``).

        Implementations should accept and ignore unknown kwargs so that
        Scanner can forward all of its parameters without knowing which ones
        each provider actually needs.
        """

    @property
    @abc.abstractmethod
    def check_classes(self) -> list[type[BaseCheck]]:
        """Return the ordered list of check classes for this provider.

        Adding a new check to an existing provider only requires updating this
        list — the Scanner and registry do not need to change.
        """

    def inventory(self, context: Any) -> list[Component]:
        """Return the list of components the scanner discovered.

        Default implementation returns ``[]`` so providers that don't
        expose an asset view still satisfy the contract. Override to
        surface the resources / files / workflows the context is
        built from — the Scanner's ``inventory()`` delegates here.
        """
        return []
