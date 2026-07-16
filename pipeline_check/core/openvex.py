"""OpenVEX ingest: parse a VEX document and match it against findings.

The consume side of the OpenVEX support (the emit side lives in
``openvex_reporter.py``). A maintainer who has triaged an OSV advisory
finding, and decided the vulnerability does not apply here or is already
remediated, records that verdict in an `OpenVEX <https://openvex.dev>`_
document and passes it with ``--vex``. This module parses that document
into a :class:`VexIndex` and answers, for each finding, "did the operator
mark this ``(vulnerability, product)`` pair ``not_affected`` or ``fixed``?"

The match is deliberately scoped to the CVE-shaped subset: only the OSV
advisory rules populate ``Finding.vulnerabilities``, so a misconfiguration
finding can never be VEX-suppressed. A matched finding is handled
baseline-style by the gate (excluded from the gated set, still reported),
so the suppression is auditable rather than silent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .checks.base import Finding

__all__ = [
    "VexError",
    "VexMatch",
    "VexIndex",
    "load_vex",
    "SUPPRESSING_STATUSES",
]

#: The two OpenVEX statuses that clear a finding. ``affected`` and
#: ``under_investigation`` are not suppressions (the vuln still applies
#: or the triage isn't done), so a document carrying them is parsed but
#: those statements never match.
SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})


class VexError(Exception):
    """A ``--vex`` document could not be read or parsed as OpenVEX."""


@dataclass(frozen=True, slots=True)
class VexMatch:
    """Why a finding was VEX-suppressed: the statement that cleared it."""

    vuln_id: str
    product: str
    status: str
    justification: str = ""

    def summary(self) -> str:
        base = f"{self.vuln_id} on {self.product}: {self.status}"
        if self.justification:
            base += f" ({self.justification})"
        return base


@dataclass(frozen=True, slots=True)
class _Statement:
    """One parsed OpenVEX statement, normalized for matching."""

    #: The vulnerability's canonical name plus every alias, so a
    #: statement keyed on a CVE still matches a finding keyed on the
    #: cross-referenced GHSA and vice versa.
    vuln_names: frozenset[str]
    #: Product identities (PURLs / subcomponent ids) the statement covers.
    products: frozenset[str]
    status: str
    justification: str = ""

    def matches(self, vuln_ids: frozenset[str], purl: str) -> bool:
        if self.status not in SUPPRESSING_STATUSES:
            return False
        if self.vuln_names.isdisjoint(vuln_ids):
            return False
        return _product_covers(self.products, purl)


@dataclass(slots=True)
class VexIndex:
    """Parsed suppressing statements from one or more OpenVEX documents."""

    statements: list[_Statement] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.statements)

    def match(self, finding: Finding) -> VexMatch | None:
        """Return the first suppressing statement that clears *finding*.

        ``None`` when nothing matches (including every non-advisory
        finding, which carries no ``vulnerabilities``).
        """
        for vref in finding.vulnerabilities:
            vuln_ids = frozenset({vref.vuln_id, *vref.aliases})
            for stmt in self.statements:
                if stmt.matches(vuln_ids, vref.purl):
                    # Report the finding's own vuln id / product so the
                    # audit line reads in the scanner's terms.
                    matched_id = next(
                        iter(vuln_ids & stmt.vuln_names), vref.vuln_id,
                    )
                    return VexMatch(
                        vuln_id=matched_id,
                        product=vref.purl,
                        status=stmt.status,
                        justification=stmt.justification,
                    )
        return None


def _product_covers(products: frozenset[str], purl: str) -> bool:
    """Whether any statement product covers the finding's PURL.

    Matches an exact PURL, a version-qualified statement product against
    a version-qualified finding PURL, and a versionless statement product
    (``pkg:npm/lodash``) that covers every version of the package (the
    "the whole package is fixed / not affected" shape).
    """
    if purl in products:
        return True
    base = purl.split("@", 1)[0]
    for prod in products:
        if prod == base or purl.startswith(prod + "@"):
            return True
    return False


def _vuln_names(vuln: Any) -> frozenset[str]:
    """Extract the name + aliases from a statement's ``vulnerability``.

    OpenVEX 0.2.0 uses an object (``{"name": "CVE-…", "aliases": [...]}``);
    the older 0.0.1 shape used a bare string. Accept both, plus an ``@id``
    fallback.
    """
    names: set[str] = set()
    if isinstance(vuln, str):
        names.add(vuln)
    elif isinstance(vuln, dict):
        for key in ("name", "@id", "id"):
            val = vuln.get(key)
            if isinstance(val, str) and val:
                names.add(val)
        aliases = vuln.get("aliases")
        if isinstance(aliases, list):
            names.update(a for a in aliases if isinstance(a, str) and a)
    return frozenset(names)


def _product_ids(products: Any) -> frozenset[str]:
    """Extract product identities from a statement's ``products``.

    Each product is either a bare PURL string, an object with ``@id``,
    or an object carrying ``identifiers.purl`` (the OpenVEX subcomponent
    shape). Collect every identity form so a document that keys on any of
    them still matches.
    """
    ids: set[str] = set()
    if not isinstance(products, list):
        return frozenset()
    for prod in products:
        if isinstance(prod, str):
            ids.add(prod)
        elif isinstance(prod, dict):
            pid = prod.get("@id")
            if isinstance(pid, str) and pid:
                ids.add(pid)
            identifiers = prod.get("identifiers")
            if isinstance(identifiers, dict):
                purl = identifiers.get("purl")
                if isinstance(purl, str) and purl:
                    ids.add(purl)
    return frozenset(ids)


def _parse_document(doc: Any, source: str) -> list[_Statement]:
    if not isinstance(doc, dict):
        raise VexError(f"{source}: not a JSON object")
    raw_statements = doc.get("statements")
    if not isinstance(raw_statements, list):
        raise VexError(f"{source}: no ``statements`` array")
    out: list[_Statement] = []
    for raw in raw_statements:
        if not isinstance(raw, dict):
            continue
        status = raw.get("status")
        if not isinstance(status, str):
            continue
        names = _vuln_names(raw.get("vulnerability"))
        products = _product_ids(raw.get("products"))
        if not names or not products:
            continue
        justification = raw.get("justification")
        out.append(_Statement(
            vuln_names=names,
            products=products,
            status=status,
            justification=justification if isinstance(justification, str) else "",
        ))
    return out


def load_vex(paths: list[str] | tuple[str, ...]) -> VexIndex:
    """Load and merge one or more OpenVEX documents into a :class:`VexIndex`.

    Raises :class:`VexError` on a missing file or malformed document, so
    a typo'd ``--vex`` path fails loudly rather than silently suppressing
    nothing.
    """
    index = VexIndex()
    for raw_path in paths:
        p = Path(raw_path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise VexError(f"{raw_path}: could not read ({exc})") from exc
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VexError(f"{raw_path}: invalid JSON ({exc})") from exc
        index.statements.extend(_parse_document(doc, raw_path))
    return index
