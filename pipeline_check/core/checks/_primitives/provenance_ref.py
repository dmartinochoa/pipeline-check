"""Extract the source ref a package's build provenance was minted from.

Shared by NPM-017 (npm sigstore attestation bundle) and PYPI-021 (PEP
740 provenance). Both wrap an in-toto Statement carrying a SLSA
provenance predicate; the ref the build ran from lives at
``predicate.buildDefinition.externalParameters.workflow.ref`` for SLSA
v1 (``...invocation.configSource.entryPoint`` carries the workflow path
in v0.2, but the ref there is in ``...environment``/``materials`` and is
not reliably present, so v0.2 is treated as unknown -> skip).

The "untrusted branch" lesson from the Red Hat npm compromise: a
latest release whose provenance was built from a throwaway branch
(``refs/heads/oidc-b67eedca``) rather than a tag or the repo's default
branch carried *valid* provenance, just from an attacker ref. This
primitive reads that ref so a consumer-side rule can flag it.

Every parse path is conservative: any missing / malformed structure
returns ``None`` (unknown -> the rule skips, never flags an unknown as
untrusted).
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any

#: Branch refs treated as a trusted default. A release built from these
#: (or from any tag) is not flagged; any other branch ref is.
_DEFAULT_BRANCH_REFS = ("refs/heads/main", "refs/heads/master")


def _statement_from_dsse_payload(payload: Any) -> dict[str, Any] | None:
    """Decode a base64 DSSE payload into its in-toto Statement dict."""
    if not isinstance(payload, str) or not payload:
        return None
    try:
        decoded = base64.b64decode(payload, validate=True)
        stmt = json.loads(decoded)
    except (ValueError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return stmt if isinstance(stmt, dict) else None


def source_ref_from_statement(stmt: dict[str, Any]) -> str | None:
    """Pull the SLSA v1 build source ref from an in-toto Statement, or None."""
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        return None
    build_def = pred.get("buildDefinition")
    if not isinstance(build_def, dict):
        return None
    ext = build_def.get("externalParameters")
    if not isinstance(ext, dict):
        return None
    workflow = ext.get("workflow")
    if isinstance(workflow, dict):
        ref = workflow.get("ref")
        if isinstance(ref, str) and ref.strip():
            return ref.strip()
    return None


def source_ref_from_npm_attestations(bundle: dict[str, Any]) -> str | None:
    """Source ref from an npm attestation bundle (``/-/npm/v1/attestations``).

    The bundle is ``{"attestations": [{"predicateType": ..., "bundle":
    {"dsseEnvelope": {"payload": <base64 in-toto statement>}}}, ...]}``.
    npm ships two attestations (a SLSA provenance and an npm publish
    attestation); we read the SLSA provenance one.
    """
    attestations = bundle.get("attestations")
    if not isinstance(attestations, list):
        return None
    for att in attestations:
        if not isinstance(att, dict):
            continue
        if "slsa.dev/provenance" not in str(att.get("predicateType", "")):
            continue
        sig_bundle = att.get("bundle")
        if not isinstance(sig_bundle, dict):
            continue
        envelope = sig_bundle.get("dsseEnvelope")
        if not isinstance(envelope, dict):
            envelope = sig_bundle.get("dsse_envelope")
        if not isinstance(envelope, dict):
            continue
        stmt = _statement_from_dsse_payload(envelope.get("payload"))
        if stmt is None:
            continue
        ref = source_ref_from_statement(stmt)
        if ref:
            return ref
    return None


def source_ref_from_pep740_provenance(provenance: dict[str, Any]) -> str | None:
    """Source ref from a PEP 740 provenance object (PyPI ``/provenance``).

    PEP 740 shape: ``{"attestation_bundles": [{"attestations":
    [{"envelope": {"statement": <base64 in-toto statement>, ...}}]}]}``.
    """
    bundles = provenance.get("attestation_bundles")
    if not isinstance(bundles, list):
        return None
    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        attestations = bundle.get("attestations")
        if not isinstance(attestations, list):
            continue
        for att in attestations:
            if not isinstance(att, dict):
                continue
            envelope = att.get("envelope")
            if not isinstance(envelope, dict):
                continue
            stmt = _statement_from_dsse_payload(envelope.get("statement"))
            if stmt is None:
                continue
            ref = source_ref_from_statement(stmt)
            if ref:
                return ref
    return None


def is_untrusted_publish_ref(ref: str) -> bool:
    """True when *ref* is a branch other than the default (main / master).

    Tags (``refs/tags/...``) and the conventional default branches are
    trusted. Any other ``refs/heads/<branch>`` is the throwaway-branch
    signal. An unrecognized ref shape is conservatively NOT flagged.
    """
    r = ref.strip()
    if r.startswith("refs/tags/"):
        return False
    if r in _DEFAULT_BRANCH_REFS:
        return False
    if r.startswith("refs/heads/"):
        return True
    return False
