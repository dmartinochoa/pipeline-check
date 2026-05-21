"""ATTEST-002. SLSA provenance source-repo claim is missing or unverifiable."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Attestation, OCIManifest

RULE = Rule(
    id="ATTEST-002",
    title="SLSA provenance source-repo claim is missing or unverifiable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345", "CWE-1357"),
    recommendation=(
        "Ensure the build emits SLSA provenance with a concrete "
        "source-repo URI plus a commit-level digest. For SLSA v0.2 "
        "that's ``predicate.invocation.configSource.uri`` + "
        "``configSource.digest`` (typically ``sha1`` for git refs). "
        "For SLSA v1, ``predicate.buildDefinition.externalParameters`` "
        "should name the workflow's source repository, and "
        "``predicate.buildDefinition.resolvedDependencies`` should "
        "include the same source pinned by digest. A missing or "
        "placeholder URI ('', 'unknown', 'n/a') leaves consumers "
        "unable to confirm what code produced the image."
    ),
    docs_note=(
        "The ``builder.id`` claim that ATTEST-001 verifies tells you "
        "*who* built the image. The source-repo claim ATTEST-002 "
        "verifies tells you *what* they built. Both are required for "
        "the SLSA chain to be meaningful: a trusted builder running "
        "an unknown source produces a signed attestation for code "
        "you can't audit.\n\n"
        "The rule walks the SLSA provenance predicate for a source "
        "URI. Path varies by spec version:\n"
        "  - v0.2: ``predicate.invocation.configSource.uri``\n"
        "  - v1.0: ``predicate.buildDefinition.externalParameters`` "
        "(builder-specific, commonly ``.workflow.repository`` or "
        "``.source.uri``)\n"
        "Fires when:\n"
        "  - no URI is present anywhere on the expected paths;\n"
        "  - the URI is a known placeholder (empty, ``?``, "
        "``unknown``, ``n/a``);\n"
        "  - the URI doesn't parse as a recognizable VCS / HTTPS "
        "shape;\n"
        "  - a URI is present but the corresponding digest field is "
        "missing or all-zeros (the bytes aren't actually pinned)."
    ),
    known_fp=(
        "Some SLSA Phase-0 attestations omit the digest field on "
        "purpose, the build was reproducible-by-source rather than "
        "pinned to a commit. Suppress via ignore-file when the "
        "team has documented this trade-off; the default expectation "
        "for any image promoted to a production registry is a "
        "concrete commit pin.",
        "Builders that emit free-form ``externalParameters`` shapes "
        "(some self-hosted SLSA implementations) may carry the "
        "source URI under a non-canonical key. The rule walks every "
        "string value in ``externalParameters`` looking for a VCS "
        "URI; if none is found, the finding fires. Add the builder "
        "to a future allowlist override (deferred) when the shape "
        "is intentional.",
    ),
    incident_refs=(
        "[SLSA v1.0 threat model](https://slsa.dev/spec/v1.0/threats) "
        "(Source-track threats): a builder pulling code from a "
        "fork or a different ref than the operator believes "
        "produces an attestation that signs the wrong bytes. "
        "The source-track threats catalog those source-substitution "
        "shapes that a pinned + verified source claim mitigates.",
        "[SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) "
        "(December 2020): the build system pulled tampered source "
        "from an unauthorized branch via SUNSPOT, producing "
        "'authentic' signed builds for code the development team "
        "never wrote. A pinned, verified source-repo claim is the "
        "control SLSA L2+ requires specifically to detect this "
        "shape.",
    ),
    exploit_example=(
        "# Vulnerable: ``configSource.uri`` is empty (or 'unknown' /\n"
        "# 'n/a' / a placeholder). The trusted builder produced and\n"
        "# signed an attestation but the source-repo claim is\n"
        "# missing, so a downstream verifier can confirm WHO built\n"
        "# but not WHAT they built. The attestation is structurally\n"
        "# valid yet semantically empty.\n"
        "{\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
        "  \"predicate\": {\n"
        "    \"builder\": { \"id\": \"https://github.com/.../generator@v2.1.0\" },\n"
        "    \"invocation\": {\n"
        "      \"configSource\": {\n"
        "        \"uri\": \"\",\n"
        "        \"digest\": {}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: concrete source-repo URI plus a commit-level\n"
        "# digest. Verifiers can now confirm the image was built\n"
        "# from the expected repository at the expected commit.\n"
        "{\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
        "  \"predicate\": {\n"
        "    \"builder\": { \"id\": \"https://github.com/.../generator@v2.1.0\" },\n"
        "    \"invocation\": {\n"
        "      \"configSource\": {\n"
        "        \"uri\": \"git+https://github.com/myorg/myrepo@refs/tags/v1.4.2\",\n"
        "        \"digest\": { \"sha1\": \"0123456789abcdef0123456789abcdef01234567\" }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


# ── Source-URI extraction (handles both SLSA v0.2 and v1) ──────────


# Matches a recognizable VCS / HTTPS source URI. Conservative: must
# start with a scheme and contain a path component (so a bare
# ``github.com`` or ``http://`` doesn't satisfy the rule).
_VCS_URI_RE = re.compile(
    r"^(git\+https?|git\+ssh|https?|ssh|git)://[^/\s]+/[^\s]+$"
)

# Tokens an attestation might carry as a placeholder when the builder
# couldn't determine the real source. Lowercased before comparison.
_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "", "?", "n/a", "na", "unknown", "none", "tbd", "todo",
})


def _looks_like_source_uri(value: str) -> bool:
    """True when *value* is a recognizable VCS / HTTPS URI."""
    return bool(_VCS_URI_RE.match(value.strip()))


def _walk_strings(node: Any) -> list[str]:
    """Yield every string leaf in a nested dict / list. Used to scan
    ``buildDefinition.externalParameters`` for a source URI when the
    canonical key isn't present (some builders use non-standard
    shapes).
    """
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(_walk_strings(v))
    elif isinstance(node, list):
        for item in node:
            out.extend(_walk_strings(item))
    return out


def _v0_2_source(predicate: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract ``(uri, digest)`` from a SLSA v0.2 predicate.

    Returns ``(None, None)`` when the canonical fields aren't
    populated. ``digest`` is the value side of the first entry in
    ``configSource.digest`` (the dict's first value), since the key
    name varies (``sha1``, ``sha256``, etc.).
    """
    invocation = predicate.get("invocation")
    if not isinstance(invocation, dict):
        return (None, None)
    config_source = invocation.get("configSource")
    if not isinstance(config_source, dict):
        return (None, None)
    uri_val = config_source.get("uri")
    uri = uri_val if isinstance(uri_val, str) else None
    digest_block = config_source.get("digest")
    digest_str: str | None = None
    if isinstance(digest_block, dict) and digest_block:
        first_val = next(iter(digest_block.values()), None)
        if isinstance(first_val, str):
            digest_str = first_val
    return (uri, digest_str)


def _v1_source(predicate: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract ``(uri, digest)`` from a SLSA v1 predicate.

    v1's ``externalParameters`` shape is builder-specific. The
    canonical GitHub Actions case stores the source repo URL under
    ``buildDefinition.externalParameters.workflow.repository``. As
    a fallback the resolver scans every string value in
    ``externalParameters`` for a VCS URI.

    Digests live separately under ``resolvedDependencies[*].digest``;
    the resolver picks the first dependency whose URI matches the
    detected source URI (or the first dependency overall if the
    source URI is None).
    """
    bd = predicate.get("buildDefinition")
    if not isinstance(bd, dict):
        return (None, None)
    ext = bd.get("externalParameters")
    uri: str | None = None
    if isinstance(ext, dict):
        # Canonical GHA shape first.
        workflow = ext.get("workflow")
        if isinstance(workflow, dict):
            repo_val = workflow.get("repository")
            if isinstance(repo_val, str) and _looks_like_source_uri(repo_val):
                uri = repo_val
        # Common alternative shape: ``source.uri``.
        if uri is None:
            source = ext.get("source")
            if isinstance(source, dict):
                src_uri = source.get("uri")
                if isinstance(src_uri, str) and _looks_like_source_uri(src_uri):
                    uri = src_uri
        # Fallback: scan every string value for a VCS URI shape.
        if uri is None:
            for s in _walk_strings(ext):
                if _looks_like_source_uri(s):
                    uri = s
                    break
    digest: str | None = None
    deps = bd.get("resolvedDependencies")
    if isinstance(deps, list):
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            digest_block = dep.get("digest")
            if not isinstance(digest_block, dict) or not digest_block:
                continue
            first = next(iter(digest_block.values()), None)
            if isinstance(first, str):
                digest = first
                break
    return (uri, digest)


def _extract_source(predicate_type: str, predicate: dict[str, Any]) -> tuple[str | None, str | None]:
    """Dispatch to the correct extractor for the predicate spec
    version. Returns ``(uri, digest)`` with ``None`` for missing
    components."""
    if predicate_type.startswith("https://slsa.dev/provenance/v0.2"):
        return _v0_2_source(predicate)
    return _v1_source(predicate)


def _classify_uri(uri: str | None) -> str:
    """Return ``'missing'``, ``'placeholder'``, ``'malformed'``, or ``'ok'``."""
    if uri is None:
        return "missing"
    stripped = uri.strip().lower()
    if stripped in _PLACEHOLDER_VALUES:
        return "placeholder"
    if not _looks_like_source_uri(uri):
        return "malformed"
    return "ok"


def _digest_pinned(digest: str | None) -> bool:
    """True when *digest* is populated and not all zeros."""
    if not digest:
        return False
    stripped = digest.strip()
    if not stripped:
        return False
    if set(stripped) <= {"0"}:
        return False
    return True


# ── Rule entry point ────────────────────────────────────────────────


def _evaluate_one(att: Attestation) -> tuple[bool, str]:
    """Return ``(ok, problem_description)`` for a single attestation."""
    uri, digest = _extract_source(att.predicate_type, att.predicate)
    verdict = _classify_uri(uri)
    if verdict == "missing":
        return False, (
            f"no source-repo URI in {att.predicate_type} predicate"
        )
    if verdict == "placeholder":
        return False, f"placeholder source URI: {uri!r}"
    if verdict == "malformed":
        return False, (
            f"source URI doesn't parse as VCS/HTTPS: {uri!r}"
        )
    if not _digest_pinned(digest):
        return False, (
            f"source URI {uri!r} is present but the digest is "
            f"missing or zero (the bytes aren't pinned)"
        )
    return True, ""


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "source-repo verification not applicable."
            ),
            recommendation="No action required.", passed=True,
        )

    slsa_attestations = [
        a for a in manifest.attestations if a.is_slsa_provenance
    ]
    if not slsa_attestations:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No SLSA provenance attestation content available "
                "to verify source-repo claim. Pass an OCI image-"
                "layout directory with a sibling ``blobs/`` tree "
                "to enable content checks; OCI-002 covers the "
                "missing-attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    problems: list[str] = []
    for att in slsa_attestations:
        ok, msg = _evaluate_one(att)
        if not ok:
            problems.append(msg)

    if not problems:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {len(slsa_attestations)} SLSA provenance "
                f"attestation(s) carry a verifiable source-repo URI "
                f"plus a non-zero digest."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(problems)} SLSA provenance attestation(s) carry an "
        f"unverifiable source-repo claim: "
        f"{'; '.join(problems[:3])}"
        f"{'…' if len(problems) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
