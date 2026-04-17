"""Shared fixtures for AWS rule-module unit tests."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.aws._catalog import ResourceCatalog


def _paginator(pages):
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


class FakeClient:
    """Thin wrapper so tests can attach per-method responses."""

    def __init__(self, **methods):
        self._responses = methods
        self._paginators: dict = {}

    def set_paginator(self, op_name: str, pages: list[dict]) -> None:
        self._paginators[op_name] = pages

    def get_paginator(self, op_name: str):
        pages = self._paginators.get(op_name, [])
        return _paginator(pages)

    def __getattr__(self, item):
        # Raise AttributeError only for dunder lookups so MagicMock-like
        # behaviour for arbitrary method names works.
        if item.startswith("__"):
            raise AttributeError(item)
        resp = self._responses.get(item)
        if resp is None:
            return MagicMock(return_value={})
        if callable(resp):
            return resp
        return MagicMock(return_value=resp)


@pytest.fixture()
def make_catalog():
    """Factory that returns a ResourceCatalog wired to fake clients.

    Usage:
        def test_x(make_catalog):
            cat = make_catalog(codebuild=FakeClient(...))
            rules.check(cat)
    """
    def _build(**clients):
        session = MagicMock()
        clients = {svc: (c or FakeClient()) for svc, c in clients.items()}

        def _pick(svc, **_kw):
            if svc not in clients:
                raise KeyError(svc)
            return clients[svc]

        session.client.side_effect = _pick
        return ResourceCatalog(session)
    return _build


def cicd_trust_doc(service="codebuild.amazonaws.com"):
    return json.dumps({
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }]
    })
