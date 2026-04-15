"""Lock in that ``tests/integration/expected_failures.json`` references
real check IDs and standards.

The localstack-test.yml workflow loads this JSON and compares the
resulting scan against its contents. If a check gets renamed or the
CIS mapping changes, the integration job won't run until a PR opens
a LocalStack-enabled workflow_dispatch — which is too late. These
tests make drift visible at unit-test time.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline_check.core import providers as _providers
from pipeline_check.core.standards.data.cis_aws_foundations import STANDARD as _CIS


MANIFEST = Path(__file__).parent / "integration" / "expected_failures.json"


@pytest.fixture(scope="module")
def spec() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _all_aws_check_ids() -> set[str]:
    """Collect every check_id the AWS provider can emit by constructing
    a real Scanner-like context and inspecting the registered classes."""
    provider = _providers.get("aws")
    assert provider is not None, "aws provider should always be registered"
    ids: set[str] = set()
    for cls in provider.check_classes:
        # Every AWS check module declares a module-level docstring
        # listing check IDs. Simpler and more robust: introspect the
        # class's run() won't work without live boto3, so just parse
        # the docstring for ``^[A-Z]+-\\d{3}`` patterns.
        import re
        doc = (cls.__module__ and __import__(cls.__module__, fromlist=[""]).__doc__) or ""
        # Check prefixes may contain digits (``S3`` is the outlier) —
        # match ``[A-Z][A-Z0-9]*-\d{3}``, not ``[A-Z]+-\d{3}``.
        for m in re.finditer(r"^([A-Z][A-Z0-9]*-\d{3})\b", doc, re.MULTILINE):
            ids.add(m.group(1))
    return ids


def test_expected_failures_reference_real_check_ids(spec):
    expected = set(spec["bad_fixture_expected_failures"])
    known = _all_aws_check_ids()
    stale = expected - known
    assert not stale, (
        f"expected_failures.json references check IDs that no longer "
        f"exist: {sorted(stale)}. Update the manifest when renaming checks."
    )


def test_cis_enrichment_matches_registered_standard(spec):
    """Every ``check_id → control_id`` entry in the manifest must be
    backed by an actual mapping in the CIS standard registry — the
    workflow relies on this being true."""
    for check_id, ctrl_id in spec["cis_enrichment_expected"].items():
        refs = _CIS.refs_for(check_id)
        got = {r.control_id for r in refs}
        assert ctrl_id in got, (
            f"CIS manifest claims {check_id} → {ctrl_id}, but the "
            f"registered standard maps {check_id} to {got or 'nothing'}. "
            f"Either update the manifest or the standard data module."
        )
