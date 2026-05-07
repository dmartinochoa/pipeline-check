"""Unit tests for the v0.4.0 Cloud Build network/IAM rules:
GCB-020 (serviceAccount points at the default Cloud Build SA),
GCB-021 (no private worker pool — build runs on the shared default).
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb020_default_sa_email as r20,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb021_no_worker_pool as r21,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


# ── GCB-020 default SA email ────────────────────────────────────────


class TestGCB020DefaultSAEmail:
    def test_fails_on_bare_default_sa_email(self):
        f = r20.check("cb.yaml", _doc(
            serviceAccount="123456789@cloudbuild.gserviceaccount.com",
        ))
        assert not f.passed
        assert "default" in f.description

    def test_fails_on_uri_form_default_sa(self):
        f = r20.check("cb.yaml", _doc(
            serviceAccount=(
                "projects/myproj/serviceAccounts/"
                "123456789@cloudbuild.gserviceaccount.com"
            ),
        ))
        assert not f.passed

    def test_passes_on_dedicated_sa_email(self):
        f = r20.check("cb.yaml", _doc(
            serviceAccount="build-pipeline@myproj.iam.gserviceaccount.com",
        ))
        assert f.passed

    def test_passes_on_uri_form_dedicated_sa(self):
        f = r20.check("cb.yaml", _doc(
            serviceAccount=(
                "projects/myproj/serviceAccounts/"
                "build-pipeline@myproj.iam.gserviceaccount.com"
            ),
        ))
        assert f.passed

    def test_passes_when_unset_so_gcb002_owns_it(self):
        # GCB-002 fires on unset; this rule defers to it instead of
        # double-counting the same problem.
        f = r20.check("cb.yaml", _doc())
        assert f.passed


# ── GCB-021 no worker pool ──────────────────────────────────────────


class TestGCB021NoWorkerPool:
    def test_fails_when_options_block_absent(self):
        f = r21.check("cb.yaml", _doc())
        assert not f.passed
        assert "default pool" in f.description

    def test_fails_when_options_block_empty(self):
        f = r21.check("cb.yaml", _doc(options={}))
        assert not f.passed

    def test_passes_with_new_style_pool_name(self):
        f = r21.check("cb.yaml", _doc(options={
            "pool": {
                "name": "projects/p/locations/us-central1/workerPools/private-pool",
            },
        }))
        assert f.passed

    def test_passes_with_legacy_worker_pool_field(self):
        f = r21.check("cb.yaml", _doc(options={
            "workerPool": (
                "projects/p/locations/us-central1/workerPools/private-pool"
            ),
        }))
        assert f.passed

    def test_fails_when_pool_name_is_empty_string(self):
        f = r21.check("cb.yaml", _doc(options={"pool": {"name": ""}}))
        assert not f.passed
