"""Azure Cloud session object, analogous to boto3.Session for AWS."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AzureCloudSession:
    """Immutable credential + subscription container.

    Constructed by :meth:`AzureCloudProvider.build_context` and passed
    to every Azure Cloud check class.  The *credential* is a
    ``DefaultAzureCredential`` (or any ``TokenCredential``); the
    *subscription_id* scopes all management-plane calls.
    """

    credential: Any
    subscription_id: str
    tenant_id: str | None = None
