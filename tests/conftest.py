"""Shared test helpers and fixtures."""

from unittest.mock import MagicMock

import boto3


def make_session(client_responses: dict | None = None) -> tuple[MagicMock, MagicMock]:
    """Return a (session, client) pair where client methods return canned responses.

    client_responses: {method_name: return_value, ...}
    For paginator-based methods pass the paginator separately via mock.

    Usage:
        session, client = make_session({"batch_get_projects": {"projects": [...]}})
    """
    session = MagicMock(spec=boto3.Session)
    client = MagicMock()
    session.client.return_value = client

    for method, response in (client_responses or {}).items():
        getattr(client, method).return_value = response

    return session, client


def make_paginator(pages: list[dict]) -> MagicMock:
    """Return a mock paginator that yields *pages* when iterated."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator
