"""External SARIF ingest — turn other scanners' SARIF output into
:class:`Finding` so it flows through the chain engine alongside
pipeline-check's native findings.

Closes the gap with hosted SaaS aggregators that compose Trivy /
Checkov / Snyk / KICS into a single dashboard. Pipeline-check
becomes the correlation tier even where another tool owns primary
detection: ingest a Trivy SARIF and the existing ``XPC-NNN`` chains
fire on the union of (pipeline-check + Trivy) findings.

Architecture
------------

The parser is deliberately format-only — it reads the SARIF 2.1.0
spec shape that every major scanner emits today, plus the
property bag conventions GitHub Code Scanning normalized in 2022:

  * ``runs[].tool.driver.{name,version}`` — identifies the source
    scanner. Used as the prefix in the synthesized check_id so
    downstream consumers can tell ``INGEST-trivy-AVD-AWS-0028``
    apart from a native ``GHA-001``.
  * ``runs[].results[].{ruleId,message,level,locations}`` — the
    per-finding payload. ``ruleId`` becomes the ``check_id``
    suffix; ``message.text`` is the description; ``level`` plus
    optional ``properties.security-severity`` map to internal
    :class:`Severity`; ``locations[].physicalLocation`` becomes
    one or more :class:`Location` rows.
  * ``runs[].tool.driver.rules[].{shortDescription,fullDescription,
    helpUri}`` — when present, the rule definition's prose
    populates the ``recommendation`` field so the operator sees
    fix guidance from the source tool inline.

What this parser is NOT:

  * Not a converter to / from pipeline-check's own SARIF output.
  * Not a dedup engine — two SARIF feeds reporting overlapping
    findings produce two ``Finding`` rows with distinct
    ``check_id`` prefixes; downstream callers can dedup by
    ``(resource, rule_canonical)`` if they want.
  * Not a validator — invalid SARIF is reported as a warning on
    the returned :class:`IngestResult` rather than raised.
    Failed-to-parse bodies fall through with empty findings so a
    misnamed file in an ``--ingest`` glob doesn't crash the scan.

Severity mapping
----------------

SARIF level → internal Severity:

  * ``error``        → HIGH (the tool considered this a finding
    that should fail a gate; default unless overridden by
    ``security-severity``).
  * ``warning``      → MEDIUM.
  * ``note``         → LOW.
  * ``none`` / unset → INFO.

Override: if ``properties.security-severity`` is present
(GitHub's CVSS-like 0..10 score), it wins over ``level``:

  * ≥ 9.0  → CRITICAL.
  * ≥ 7.0  → HIGH.
  * ≥ 4.0  → MEDIUM.
  * ≥ 0.1  → LOW.
  * < 0.1  → INFO.

This mirrors GitHub Code Scanning's own bucketization so the
ingested-finding severities line up with how the source tool is
already presented in the GHCS UI.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .checks.base import Confidence, Finding, Location, Severity

#: Cap on bytes read per SARIF file. SARIF documents from real
#: scanners top out at low MB even for large repos; anything
#: larger is either misformatted or attacker-controlled and we'd
#: rather skip than blow scanner memory.
_MAX_SARIF_BYTES = 25 * 1024 * 1024

#: Cap on number of results processed per file. Acts as a guard
#: against accidentally loading a huge dump (e.g., a Trivy CVE
#: scan against a kitchen-sink container with thousands of CVEs)
#: and overwhelming the chain-engine cross-product. Configurable
#: via the public function arg if a caller really needs more.
_DEFAULT_MAX_RESULTS = 5_000


@dataclass(slots=True)
class IngestResult:
    """The output of parsing one SARIF file.

    ``findings`` is the converted Finding list — empty when the
    file was malformed or contained no results. ``warnings`` carries
    one-line strings the caller surfaces under ``ctx.warnings`` so
    parse failures are visible without raising.

    ``source`` and ``source_version`` come from the SARIF document's
    own ``runs[].tool.driver.{name,version}`` so the operator can
    see in the report which feed produced which finding (and which
    version of which tool).
    """

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source: str = ""
    source_version: str = ""
    file_path: str = ""


# ── SARIF level / severity mapping ────────────────────────────────────


_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error":   Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note":    Severity.LOW,
    "none":    Severity.INFO,
}


def _severity_from_security_severity(score_str: str) -> Severity | None:
    """Convert a SARIF ``properties.security-severity`` score to
    internal Severity. Returns ``None`` when the value isn't a
    parseable float so the caller falls back to level-based
    mapping."""
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


def _resolve_severity(
    level: str | None, properties: dict[str, Any] | None,
) -> Severity:
    """Pick severity using security-severity override first, then
    SARIF level, then INFO fallback."""
    if isinstance(properties, dict):
        sec = properties.get("security-severity")
        if sec is not None:
            mapped = _severity_from_security_severity(str(sec))
            if mapped is not None:
                return mapped
    if isinstance(level, str):
        mapped_level = _LEVEL_TO_SEVERITY.get(level.lower())
        if mapped_level is not None:
            return mapped_level
    return Severity.INFO


# ── Source / driver normalization ─────────────────────────────────────


_TOOL_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _normalize_tool_name(raw: str) -> str:
    """Lowercase + slug the tool name so check_ids stay
    grep-friendly. ``Trivy`` → ``trivy``, ``CFN-NAG`` →
    ``cfn-nag``, ``CodeQL CLI`` → ``codeql-cli``."""
    if not raw:
        return "unknown"
    slug = _TOOL_SLUG_RE.sub("-", raw.strip().lower()).strip("-")
    return slug or "unknown"


def _make_check_id(tool_slug: str, rule_id: str) -> str:
    """Build the synthesized internal check_id for an ingested
    finding. Format: ``INGEST-<tool>-<rule-id>``.

    The ``INGEST-`` prefix lets every reporter and the chain
    engine tell ingested findings apart from native ones at a
    glance. The tool slug preserves provenance so two SARIF
    feeds reporting overlapping rule IDs (Checkov and KICS both
    have ``CKV2_AWS_*``) don't collide."""
    safe_rule = (rule_id or "unknown").strip()
    if not safe_rule:
        safe_rule = "unknown"
    # Avoid double-stuffing the prefix when the SARIF source
    # already wrote one (some tools' SARIF wrap their rule IDs).
    if safe_rule.upper().startswith("INGEST-"):
        return safe_rule
    return f"INGEST-{tool_slug}-{safe_rule}"


# ── Locations ────────────────────────────────────────────────────────


def _locations_from_sarif(
    sarif_locations: list[Any] | None,
) -> list[Location]:
    """Convert SARIF ``locations[].physicalLocation`` to internal
    :class:`Location` rows. The SARIF spec allows multiple physical
    locations per result (e.g., CodeQL data-flow paths); each
    becomes a separate :class:`Location`. Logical locations
    (function name only, no file) are dropped — pipeline-check's
    Location type requires a path."""
    out: list[Location] = []
    if not isinstance(sarif_locations, list):
        return out
    for loc in sarif_locations:
        if not isinstance(loc, dict):
            continue
        phys = loc.get("physicalLocation")
        if not isinstance(phys, dict):
            continue
        artifact = phys.get("artifactLocation")
        if not isinstance(artifact, dict):
            continue
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        region = phys.get("region")
        start_line: int | None = None
        end_line: int | None = None
        if isinstance(region, dict):
            sl = region.get("startLine")
            el = region.get("endLine")
            if isinstance(sl, int) and sl > 0:
                start_line = sl
            if isinstance(el, int) and el > 0:
                end_line = el
        out.append(Location(
            path=uri,
            start_line=start_line,
            end_line=end_line,
        ))
    return out


# ── Rule prose lookup ───────────────────────────────────────────────


def _build_rule_index(rules: list[Any] | None) -> dict[str, dict[str, Any]]:
    """Index ``runs[].tool.driver.rules`` by ``id`` so the result
    converter can pull the rule's title / description / helpUri
    without re-walking the rules array per result."""
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(rules, list):
        return out
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        rule_id = entry.get("id")
        if isinstance(rule_id, str) and rule_id:
            out[rule_id] = entry
    return out


def _rule_prose(rule_def: dict[str, Any] | None) -> tuple[str, str]:
    """Return ``(title, recommendation)`` from a SARIF rule
    definition. Both fall back to empty strings when absent."""
    if not isinstance(rule_def, dict):
        return "", ""
    title = ""
    short = rule_def.get("shortDescription")
    if isinstance(short, dict):
        text = short.get("text")
        if isinstance(text, str):
            title = text.strip()
    full = rule_def.get("fullDescription")
    rec = ""
    if isinstance(full, dict):
        text = full.get("text")
        if isinstance(text, str):
            rec = text.strip()
    if not rec:
        # Some tools put the fix guidance under ``help.text`` /
        # ``help.markdown`` instead of fullDescription.
        help_block = rule_def.get("help")
        if isinstance(help_block, dict):
            text = help_block.get("text") or help_block.get("markdown")
            if isinstance(text, str):
                rec = text.strip()
    return title, rec


# ── Public entry points ────────────────────────────────────────────


def parse_sarif_text(
    text: str,
    file_path: str = "<inline>",
    max_results: int = _DEFAULT_MAX_RESULTS,
) -> IngestResult:
    """Parse a SARIF document body and convert every result to a
    :class:`Finding`. Never raises; bad input lands in
    :attr:`IngestResult.warnings`.
    """
    result = IngestResult(file_path=file_path)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(
            f"[ingest] {file_path}: JSON parse error: "
            f"{str(exc).split(chr(10), 1)[0]}"
        )
        return result
    if not isinstance(doc, dict):
        result.warnings.append(
            f"[ingest] {file_path}: top-level is not a JSON object"
        )
        return result
    if not isinstance(doc.get("version"), str) or \
            not str(doc.get("version", "")).startswith("2."):
        # We're permissive — older SARIF 1.x is rare in CI tooling
        # but a missing version is common (some tools omit it).
        # Surface a warning, don't bail.
        result.warnings.append(
            f"[ingest] {file_path}: missing or non-2.x ``version`` "
            f"field; parsing best-effort."
        )
    runs = doc.get("runs")
    if not isinstance(runs, list):
        result.warnings.append(
            f"[ingest] {file_path}: missing ``runs`` array; nothing "
            f"to ingest."
        )
        return result
    total_results = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver: dict[str, Any] = {}
        if isinstance(tool, dict):
            d = tool.get("driver")
            if isinstance(d, dict):
                driver = d
        tool_name_raw = ""
        if isinstance(driver.get("name"), str):
            tool_name_raw = driver["name"]
        tool_slug = _normalize_tool_name(tool_name_raw)
        # Capture the source name on the first non-empty hit; later
        # runs with different drivers share the same IngestResult
        # but the synthesized check_id preserves per-finding
        # provenance.
        if not result.source and tool_slug != "unknown":
            result.source = tool_slug
        if not result.source_version:
            ver = driver.get("version")
            if isinstance(ver, str):
                result.source_version = ver
        rule_index = _build_rule_index(driver.get("rules"))
        results_arr = run.get("results")
        if not isinstance(results_arr, list):
            continue
        for raw_result in results_arr:
            if not isinstance(raw_result, dict):
                continue
            if total_results >= max_results:
                result.warnings.append(
                    f"[ingest] {file_path}: hit max_results cap "
                    f"({max_results}); some findings dropped."
                )
                return result
            total_results += 1
            finding = _convert_result(
                raw_result, rule_index, tool_slug, file_path,
            )
            if finding is not None:
                result.findings.append(finding)
    return result


def parse_sarif_file(
    path: str | Path, max_results: int = _DEFAULT_MAX_RESULTS,
) -> IngestResult:
    """Read a SARIF file from disk, parse it, return the result.
    Same no-raise contract as :func:`parse_sarif_text`."""
    p = Path(path)
    result = IngestResult(file_path=str(p))
    if not p.exists():
        result.warnings.append(
            f"[ingest] {p}: file does not exist."
        )
        return result
    try:
        size = p.stat().st_size
    except OSError as exc:
        result.warnings.append(f"[ingest] {p}: stat failed: {exc}")
        return result
    if size > _MAX_SARIF_BYTES:
        result.warnings.append(
            f"[ingest] {p}: file size {size} bytes exceeds the "
            f"{_MAX_SARIF_BYTES}-byte cap; skipped."
        )
        return result
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.warnings.append(f"[ingest] {p}: read failed: {exc}")
        return result
    parsed = parse_sarif_text(text, str(p), max_results=max_results)
    # Carry the file_path through; parse_sarif_text uses the
    # passed-in value already so no override needed.
    return parsed


# ── Result -> Finding conversion ─────────────────────────────────


def _convert_result(
    raw: dict[str, Any],
    rule_index: dict[str, dict[str, Any]],
    tool_slug: str,
    source_path: str,
) -> Finding | None:
    """Convert one SARIF ``result`` entry to a :class:`Finding`.
    Returns ``None`` only when both the ``ruleId`` and the
    ``message`` are missing — the entry is then unusable. A
    message-only entry is kept (with a synthesized ``check_id``)
    so the best-effort ingest contract holds for tools that emit
    free-form findings without rule metadata."""
    rule_id = raw.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        # Some tools emit results with a ``rule.id`` nested
        # field instead of the top-level ruleId. Accept either.
        rule_block = raw.get("rule")
        if isinstance(rule_block, dict):
            inner = rule_block.get("id")
            if isinstance(inner, str) and inner:
                rule_id = inner
    message = raw.get("message")
    description = ""
    if isinstance(message, dict):
        text = message.get("text")
        if isinstance(text, str):
            description = text.strip()
    if not isinstance(rule_id, str) or not rule_id:
        # No rule ID — only salvage the entry if a non-empty
        # ``message.text`` survived. Synthesize a stable check_id
        # from a short hash of the message so two identical
        # message-only entries collapse to one check_id (and stay
        # distinct from real rules).
        if not description:
            return None
        import hashlib
        digest = hashlib.sha256(
            description.encode("utf-8", errors="replace"),
        ).hexdigest()[:10]
        rule_id = f"message-only-{digest}"
    check_id = _make_check_id(tool_slug, rule_id)
    rule_def = rule_index.get(rule_id)
    title, recommendation = _rule_prose(rule_def)
    if not title:
        # Fall back to the ruleId itself so the column is never
        # empty; the description carries the full message anyway.
        title = rule_id
    if not description:
        description = (
            f"Reported by {tool_slug} (rule {rule_id}). "
            f"See source SARIF for details."
        )
    severity = _resolve_severity(
        raw.get("level"), raw.get("properties"),
    )
    locations = _locations_from_sarif(raw.get("locations"))
    # Resource handle: prefer the first location's URI; otherwise
    # fall back to the source SARIF file path so the finding has
    # a stable group key for the heatmap and reporters.
    resource = locations[0].path if locations else source_path
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        resource=resource,
        description=description,
        recommendation=recommendation,
        passed=False,
        confidence=Confidence.MEDIUM,
        locations=locations,
    )
