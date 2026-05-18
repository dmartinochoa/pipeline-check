"""Tests for ``ResourceCatalog.codeartifact_package_versions``.

The freshness primitive walks ``list_packages`` →
``list_package_versions`` → ``describe_package_version`` per repo and
returns a flat list of per-version dicts. Future cooldown rules
(CA-005 fresh-public-fetch, related variants) sit on top of this
data; the catalog itself stays a no-policy inventory layer.

These tests drive the primitive through the shared ``FakeClient``
fixture so the boto contract is exercised without a network call.
"""
from __future__ import annotations

from datetime import UTC, datetime

from tests.aws.rules.conftest import FakeClient


def _client_with_versions(
    packages_by_repo,
    versions_by_pkg,
    describe_responses,
):
    """Build a CodeArtifact ``FakeClient`` from three nested dicts:

      * ``packages_by_repo``: ``{(domain, repo): [list_packages page, ...]}``
      * ``versions_by_pkg``: ``{(domain, repo, fmt, pkg): [list_package_versions page, ...]}``
      * ``describe_responses``: ``{(domain, repo, fmt, pkg, version): describe_package_version body}``
    """
    client = FakeClient()

    def list_packages_paginator(**kwargs):
        domain = kwargs["domain"]
        repo = kwargs["repository"]
        from unittest.mock import MagicMock
        p = MagicMock()
        p.paginate.return_value = iter(
            packages_by_repo.get((domain, repo), []),
        )
        return p

    def list_versions_paginator(**kwargs):
        domain = kwargs["domain"]
        repo = kwargs["repository"]
        fmt = kwargs["format"]
        pkg = kwargs["package"]
        from unittest.mock import MagicMock
        p = MagicMock()
        p.paginate.return_value = iter(
            versions_by_pkg.get((domain, repo, fmt, pkg), []),
        )
        return p

    def get_paginator(op_name: str):
        if op_name == "list_packages":
            from unittest.mock import MagicMock
            outer = MagicMock()
            outer.paginate.side_effect = (
                lambda **kw: list_packages_paginator(**kw).paginate()
            )
            return outer
        if op_name == "list_package_versions":
            from unittest.mock import MagicMock
            outer = MagicMock()
            outer.paginate.side_effect = (
                lambda **kw: list_versions_paginator(**kw).paginate()
            )
            return outer
        # list_repositories / list_domains aren't exercised here but
        # the FakeClient base would error without a stub, so return an
        # empty paginator for anything we didn't wire.
        from unittest.mock import MagicMock
        empty = MagicMock()
        empty.paginate.return_value = iter([])
        return empty

    def describe_package_version(**kwargs):
        key = (
            kwargs["domain"], kwargs["repository"],
            kwargs["format"], kwargs["package"],
            kwargs["packageVersion"],
        )
        return describe_responses[key]

    client.get_paginator = get_paginator
    client.describe_package_version = describe_package_version
    return client


def test_returns_per_version_dicts_for_one_repo(make_catalog):
    published = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    client = _client_with_versions(
        packages_by_repo={
            ("d", "r"): [
                {"packages": [{"format": "npm", "package": "lodash"}]},
            ],
        },
        versions_by_pkg={
            ("d", "r", "npm", "lodash"): [
                {"versions": [
                    {"version": "4.17.21", "status": "Published"},
                ]},
            ],
        },
        describe_responses={
            ("d", "r", "npm", "lodash", "4.17.21"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {
                        "originType": "EXTERNAL",
                        "domainEntryPoint": {
                            "externalConnectionName": "public:npmjs",
                        },
                    },
                },
            },
        },
    )
    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions([("d", "r")])
    assert out == [{
        "domain": "d",
        "repository": "r",
        "format": "npm",
        "namespace": None,
        "package": "lodash",
        "version": "4.17.21",
        "status": "Published",
        "publishedTime": published,
        "originType": "EXTERNAL",
        "originName": "public:npmjs",
    }]


def test_skips_non_published_versions(make_catalog):
    """``Disposed`` / ``Unfinished`` versions aren't candidates for
    cooldown gating and shouldn't burn a ``describe`` call."""
    client = _client_with_versions(
        packages_by_repo={
            ("d", "r"): [
                {"packages": [{"format": "pypi", "package": "requests"}]},
            ],
        },
        versions_by_pkg={
            ("d", "r", "pypi", "requests"): [
                {"versions": [
                    {"version": "1.0.0", "status": "Disposed"},
                    {"version": "1.0.1", "status": "Unfinished"},
                ]},
            ],
        },
        describe_responses={},  # No describe should be called.
    )
    cat = make_catalog(codeartifact=client)
    assert cat.codeartifact_package_versions([("d", "r")]) == []


def test_only_external_filters_internal_origins(make_catalog):
    published = datetime(2026, 5, 1, tzinfo=UTC)
    client = _client_with_versions(
        packages_by_repo={
            ("d", "r"): [
                {"packages": [
                    {"format": "npm", "package": "lodash"},
                    {"format": "npm", "package": "internal-tool"},
                ]},
            ],
        },
        versions_by_pkg={
            ("d", "r", "npm", "lodash"): [
                {"versions": [{"version": "4.17.21", "status": "Published"}]},
            ],
            ("d", "r", "npm", "internal-tool"): [
                {"versions": [{"version": "0.1.0", "status": "Published"}]},
            ],
        },
        describe_responses={
            ("d", "r", "npm", "lodash", "4.17.21"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {
                        "originType": "EXTERNAL",
                        "domainEntryPoint": {
                            "externalConnectionName": "public:npmjs",
                        },
                    },
                },
            },
            ("d", "r", "npm", "internal-tool", "0.1.0"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {"originType": "INTERNAL"},
                },
            },
        },
    )
    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions(
        [("d", "r")], only_external=True,
    )
    assert {row["package"] for row in out} == {"lodash"}


def test_cap_bounds_describe_call_count(make_catalog):
    """``max_versions_per_package`` should stop the describe fanout
    once N candidates have been described, leaving older versions
    alone."""
    described_keys: list[tuple] = []
    described_template = {
        "packageVersion": {
            "publishedTime": datetime(2026, 1, 1, tzinfo=UTC),
            "origin": {"originType": "INTERNAL"},
        },
    }
    versions_listing = [
        {"versions": [
            {"version": f"1.0.{i}", "status": "Published"}
            for i in range(20)
        ]},
    ]
    describe_responses = {
        ("d", "r", "pypi", "many", f"1.0.{i}"): described_template
        for i in range(20)
    }
    client = _client_with_versions(
        packages_by_repo={
            ("d", "r"): [
                {"packages": [{"format": "pypi", "package": "many"}]},
            ],
        },
        versions_by_pkg={("d", "r", "pypi", "many"): versions_listing},
        describe_responses=describe_responses,
    )

    # Wrap describe to count invocations.
    original_describe = client.describe_package_version

    def counting_describe(**kwargs):
        described_keys.append(kwargs["packageVersion"])
        return original_describe(**kwargs)

    client.describe_package_version = counting_describe

    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions(
        [("d", "r")], max_versions_per_package=3,
    )
    assert len(out) == 3
    assert len(described_keys) == 3


def test_iterates_multiple_repositories(make_catalog):
    published = datetime(2026, 5, 1, tzinfo=UTC)
    client = _client_with_versions(
        packages_by_repo={
            ("d", "alpha"): [
                {"packages": [{"format": "npm", "package": "a"}]},
            ],
            ("d", "beta"): [
                {"packages": [{"format": "pypi", "package": "b"}]},
            ],
        },
        versions_by_pkg={
            ("d", "alpha", "npm", "a"): [
                {"versions": [{"version": "1.0.0", "status": "Published"}]},
            ],
            ("d", "beta", "pypi", "b"): [
                {"versions": [{"version": "0.1.0", "status": "Published"}]},
            ],
        },
        describe_responses={
            ("d", "alpha", "npm", "a", "1.0.0"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {"originType": "INTERNAL"},
                },
            },
            ("d", "beta", "pypi", "b", "0.1.0"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {"originType": "INTERNAL"},
                },
            },
        },
    )
    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions(
        [("d", "alpha"), ("d", "beta")],
    )
    assert {(row["repository"], row["package"]) for row in out} == {
        ("alpha", "a"), ("beta", "b"),
    }


def test_namespace_threaded_through_when_present(make_catalog):
    """Maven / generic formats use a namespace; the primitive should
    propagate it through the list/describe calls and into the output."""
    published = datetime(2026, 5, 1, tzinfo=UTC)
    client = _client_with_versions(
        packages_by_repo={
            ("d", "r"): [
                {"packages": [{
                    "format": "maven",
                    "namespace": "com.example",
                    "package": "lib",
                }]},
            ],
        },
        versions_by_pkg={
            ("d", "r", "maven", "lib"): [
                {"versions": [{"version": "1.0.0", "status": "Published"}]},
            ],
        },
        describe_responses={
            ("d", "r", "maven", "lib", "1.0.0"): {
                "packageVersion": {
                    "publishedTime": published,
                    "origin": {"originType": "INTERNAL"},
                },
            },
        },
    )

    # Wrap describe to verify the namespace flows through.
    original_describe = client.describe_package_version
    describe_kwargs: dict = {}

    def recording_describe(**kwargs):
        describe_kwargs.update(kwargs)
        return original_describe(**kwargs)

    client.describe_package_version = recording_describe

    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions([("d", "r")])
    assert out and out[0]["namespace"] == "com.example"
    assert describe_kwargs.get("namespace") == "com.example"


def test_client_error_per_repo_is_swallowed(make_catalog):
    """A ``ClientError`` from one repo's paginator records the error
    on the catalog and continues with the other repos rather than
    aborting the primitive."""
    from unittest.mock import MagicMock

    from botocore.exceptions import ClientError
    raising_paginator = MagicMock()
    raising_paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "boom"}},
        "ListPackages",
    )

    def get_paginator(op_name: str):
        if op_name == "list_packages":
            return raising_paginator
        empty = MagicMock()
        empty.paginate.return_value = iter([])
        return empty

    client = FakeClient()
    client.get_paginator = get_paginator
    cat = make_catalog(codeartifact=client)
    out = cat.codeartifact_package_versions([("d", "r")])
    assert out == []
    assert "codeartifact" in cat.errors
