"""GCP session object, analogous to boto3.Session for AWS."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GCPSession:
    """Immutable credential + project container.

    Constructed by :meth:`GCPProvider.build_context` and passed to
    every GCP check class.  The *credentials* come from
    ``google.auth.default()``; the *project_id* scopes all resource
    enumeration calls.
    """

    credentials: Any
    project_id: str
