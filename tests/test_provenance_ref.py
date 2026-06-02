"""Tests for the shared build-provenance source-ref extractor.

Synthetic DSSE / in-toto / SLSA-v1 fixtures (we have no real attestation
bundles checked in); the parser is exercised against the documented
shapes for the npm sigstore bundle and the PEP 740 provenance object.
"""
from __future__ import annotations

import base64
import json

from pipeline_check.core.checks._primitives.provenance_ref import (
    is_untrusted_publish_ref,
    source_ref_from_npm_attestations,
    source_ref_from_pep740_provenance,
    source_ref_from_statement,
)


def _statement(ref: str) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {
                        "ref": ref,
                        "repository": "https://github.com/acme/widget",
                        "path": ".github/workflows/release.yml",
                    }
                }
            }
        },
    }


def _b64(stmt: dict) -> str:
    return base64.b64encode(json.dumps(stmt).encode()).decode()


def _npm_bundle(ref: str) -> dict:
    return {
        "attestations": [
            # npm ships a publish attestation alongside the provenance one;
            # the parser must pick the SLSA provenance attestation.
            {"predicateType": "https://github.com/npm/attestation/publish/v0.1",
             "bundle": {"dsseEnvelope": {"payload": _b64({"predicate": {}})}}},
            {"predicateType": "https://slsa.dev/provenance/v1",
             "bundle": {"dsseEnvelope": {"payload": _b64(_statement(ref))}}},
        ]
    }


def _pep740(ref: str) -> dict:
    return {
        "attestation_bundles": [
            {"attestations": [{"envelope": {"statement": _b64(_statement(ref))}}]}
        ]
    }


class TestStatementExtraction:
    def test_source_ref_from_statement(self):
        assert source_ref_from_statement(
            _statement("refs/heads/oidc-b67eedca")
        ) == "refs/heads/oidc-b67eedca"

    def test_missing_predicate_returns_none(self):
        assert source_ref_from_statement({"_type": "x"}) is None

    def test_missing_workflow_returns_none(self):
        assert source_ref_from_statement(
            {"predicate": {"buildDefinition": {"externalParameters": {}}}}
        ) is None


class TestNpmBundle:
    def test_extracts_ref_from_slsa_attestation(self):
        assert source_ref_from_npm_attestations(
            _npm_bundle("refs/heads/oidc-b67eedca")
        ) == "refs/heads/oidc-b67eedca"

    def test_tag_ref(self):
        assert source_ref_from_npm_attestations(
            _npm_bundle("refs/tags/v1.4.0")
        ) == "refs/tags/v1.4.0"

    def test_no_attestations_returns_none(self):
        assert source_ref_from_npm_attestations({}) is None
        assert source_ref_from_npm_attestations({"attestations": []}) is None

    def test_bad_base64_returns_none(self):
        bundle = {"attestations": [{
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {"dsseEnvelope": {"payload": "!!!not-base64!!!"}},
        }]}
        assert source_ref_from_npm_attestations(bundle) is None


class TestPep740:
    def test_extracts_ref(self):
        assert source_ref_from_pep740_provenance(
            _pep740("refs/heads/oidc-deadbeef")
        ) == "refs/heads/oidc-deadbeef"

    def test_empty_returns_none(self):
        assert source_ref_from_pep740_provenance({}) is None


class TestUntrustedRef:
    def test_throwaway_branch_is_untrusted(self):
        assert is_untrusted_publish_ref("refs/heads/oidc-b67eedca") is True

    def test_arbitrary_branch_is_untrusted(self):
        assert is_untrusted_publish_ref("refs/heads/feature-x") is True

    def test_tag_is_trusted(self):
        assert is_untrusted_publish_ref("refs/tags/v1.2.3") is False

    def test_default_branches_trusted(self):
        assert is_untrusted_publish_ref("refs/heads/main") is False
        assert is_untrusted_publish_ref("refs/heads/master") is False

    def test_unknown_shape_not_flagged(self):
        # Conservative: an unrecognized ref shape is not flagged.
        assert is_untrusted_publish_ref("HEAD") is False
        assert is_untrusted_publish_ref("") is False
