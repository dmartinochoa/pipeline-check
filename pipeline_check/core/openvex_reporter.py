"""OpenVEX emit: serialize advisory findings as an OpenVEX document.

The produce side of the OpenVEX support (the consume side lives in
``openvex.py``). Every OSV advisory finding the scan raised is a claim
that a known vulnerability affects a product the pipeline pulls in, which
is exactly an OpenVEX ``affected`` statement. Emitting the scan's findings
in that exchange format lets a downstream consumer carry the verdicts,
combine them with their own triage, and feed a ``not_affected`` / ``fixed``
document straight back into ``--vex`` on the next run.

Scoped to the CVE-shaped subset: only findings carrying structured
``vulnerabilities`` (the OSV rules) contribute, so a misconfiguration
finding never lands in the VEX output.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .checks.base import Finding

__all__ = ["report_openvex"]

_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_AUTHOR = "pipeline-check"
_ROLE = "Software Composition Analysis Tool"


def _collect(findings: Iterable[Finding]) -> dict[str, tuple[set[str], set[str]]]:
    """Group failing advisory findings into ``vuln_id -> (aliases, purls)``."""
    grouped: dict[str, tuple[set[str], set[str]]] = {}
    for f in findings:
        if f.passed:
            continue
        for vref in f.vulnerabilities:
            aliases, purls = grouped.setdefault(vref.vuln_id, (set(), set()))
            aliases.update(vref.aliases)
            purls.add(vref.purl)
    return grouped


def report_openvex(
    findings: Iterable[Finding],
    tool_version: str = "",
    scanned_path: str = ".",
    now: datetime | None = None,
) -> str:
    """Serialize the advisory *findings* as an OpenVEX 0.2.0 JSON string.

    ``now`` is injectable so the document timestamp is deterministic under
    test; it defaults to the current UTC time. The document ``@id`` is a
    content hash of the statements, so re-running on the same findings
    yields a stable id regardless of the timestamp.
    """
    findings = list(findings)
    grouped = _collect(findings)

    statements: list[dict[str, Any]] = []
    for vuln_id in sorted(grouped):
        aliases, purls = grouped[vuln_id]
        vulnerability: dict[str, Any] = {"name": vuln_id}
        # A vuln id can appear among its own aliases (OSV cross-refs);
        # drop it so the alias list is strictly the other identifiers.
        extra = sorted(a for a in aliases if a and a != vuln_id)
        if extra:
            vulnerability["aliases"] = extra
        statements.append({
            "vulnerability": vulnerability,
            "products": [{"@id": purl} for purl in sorted(purls)],
            "status": "affected",
        })

    timestamp = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc: dict[str, Any] = {
        "@context": _CONTEXT,
        "@id": _document_id(statements),
        "author": _AUTHOR,
        "role": _ROLE,
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"pipeline-check {tool_version or '0.0.0'}",
        "statements": statements,
    }
    return json.dumps(doc, indent=2)


def _document_id(statements: list[dict[str, Any]]) -> str:
    """A deterministic ``@id`` derived from the statement content."""
    payload = json.dumps(statements, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"https://openvex.dev/docs/pipeline-check-{digest[:32]}"
