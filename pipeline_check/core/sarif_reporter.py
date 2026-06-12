"""SARIF 2.1.0 reporter.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
consumed by GitHub Advanced Security, GitLab SAST, Azure DevOps, and
every major SAST aggregator. Emitting SARIF turns pipeline_check findings
into code-scanning alerts inline on pull requests without any custom
integration.

Key shape notes:

- Only **failed** findings become ``results``. SARIF's convention is
  that a rule with no results is a passing / not-triggered check.
- Every distinct ``check_id`` is declared once under
  ``runs[0].tool.driver.rules`` with its title, description, help, and
  default severity. Results then reference rules by index + id.
- Severity is expressed two ways: the enum ``level`` (error/warning/note)
  for UI coloring, and the floating-point ``security-severity``
  (0–10 CVSS-style) that GitHub uses to filter code-scanning alerts.
- Compliance controls attached by the Scanner are split across two
  SARIF fields: rule-level ``properties.tags`` carries the *standard
  slugs* (e.g. ``owasp_cicd_top_10``, ``soc2``) so GitHub's code-
  scanning UI can filter by standard; individual *control IDs*
  (``CICD-SEC-6``, ``CC6.1``, ``Dangerous-Workflow``) live only on the
  per-result ``properties.controls`` array. GitHub caps rule tags at
  10, the docstring formerly said 20, but a SARIF upload exceeding
  10 tags surfaces a runtime warning and silently drops the
  overflow, which is why the cap is enforced here. Tags that get
  truncated are still present in full on ``properties.controls``.
- Each result carries a ``partialFingerprints`` map so GitHub Code
  Scanning, Azure DevOps, and other SARIF consumers can dedupe
  findings across runs. Fingerprints are content-based: two scans of
  an unchanged repo produce identical fingerprints, so an existing
  alert stays open instead of resolving + re-opening on every push.
  Touching an unrelated line elsewhere in the file leaves the
  fingerprint stable; touching the offending line itself produces a
  new fingerprint, which is the signal GHCS uses to resolve the
  prior alert and file a fresh one. See :func:`_finding_fingerprints`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
from typing import Any

from .chains import Chain
from .checks.base import (
    Confidence,
    Finding,
    Location,
    Severity,
    inline_exploit,
    markdown_code_fence,
)
from .report_view import ReportView
from .scorer import ScoreResult

# SARIF 2.1.0 ``rank`` is a 0–100 float conveying "how important this
# result is" independent of severity. GitHub Code Scanning surfaces it
# as a sortable column. Map confidence directly: HIGH-confidence
# findings are ranked at 100 so they float to the top of the UI;
# LOW-confidence noise sinks to 20.
_CONFIDENCE_RANK: dict[Confidence, float] = {
    Confidence.HIGH: 100.0,
    Confidence.MEDIUM: 50.0,
    Confidence.LOW: 20.0,
}

#: GitHub Code Scanning's hard cap on per-rule SARIF tags. Uploads
#: that exceed it warn ``Rule tags in SARIF file exceed limits`` and
#: silently drop the overflow. Tags above the cap are still preserved
#: in ``properties.controls`` (per finding) and ``properties.standards``
#: (when applicable) for full audit fidelity.
_MAX_RULE_TAGS = 10

#: Priority slugs surface first within the truncated tag list so
#: filter-by-standard in GitHub's code-scanning UI keeps working for
#: the most commonly searched frameworks even when overall tag count
#: exceeds the cap. Anything not in this list sorts alphabetically
#: after these. Order reflects user-facing relevance, not severity.
_TAG_PRIORITY: tuple[str, ...] = (
    "owasp_cicd_top_10",
    "nist_ssdf",
    "slsa",
    "cis_supply_chain",
    "openssf_scorecard",
)


def _ordered_tags(standards: set[str]) -> list[str]:
    """Return ``standards`` ordered priority-first then alphabetical."""
    priority_present = [s for s in _TAG_PRIORITY if s in standards]
    rest = sorted(standards - set(_TAG_PRIORITY))
    return priority_present + rest

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/dmartinochoa/pipeline-check"


# Severity → (SARIF level, GitHub security-severity score).
#
# ``level`` drives the UI coloring and is one of error / warning / note.
# ``security-severity`` is a 0.0–10.0 numeric that GitHub's code scanning
# alert filters use. Keep these rankings consistent with the CLI's
# --severity-threshold ordering in base.py.
_LEVEL_MAP: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("error", "9.5"),
    Severity.HIGH:     ("error", "7.5"),
    Severity.MEDIUM:   ("warning", "5.5"),
    Severity.LOW:      ("warning", "3.0"),
    Severity.INFO:     ("note", "1.0"),
}


def report_sarif(
    findings: list[Finding],
    score_result: ScoreResult,
    tool_version: str = "",
    chains: list[Chain] | None = None,
    inline_explain: bool = False,
    scan_status: dict[str, Any] | None = None,
) -> str:
    """Serialize findings to a SARIF 2.1.0 JSON string.

    Parameters
    ----------
    findings:
        The full set of findings from the scanner, both passed and
        failed. Passed findings are used to complete the rule catalog
        but do not emit results.
    score_result:
        The dict returned by ``score()``. Surfaced as run-level
        ``properties`` so SARIF consumers can filter by overall grade.
    tool_version:
        Version string to embed as ``driver.version``. Pass
        ``pipeline_check.__version__`` from the CLI.
    chains:
        Optional attack chains from ``Scanner.chains``. Each chain
        becomes its own SARIF rule + result so GitHub Code Scanning
        surfaces it as a top-level alert. Triggering check IDs are
        carried in ``properties.triggering_checks`` for programmatic
        consumers; MITRE ATT&CK techniques are encoded as ``tags``
        prefixed with ``mitre/``.
    scan_status:
        Optional completeness summary (``complete`` plus the
        files-scanned / unparsed / degraded counts). Surfaced under the
        run's ``properties.scan_status`` so a consumer can detect a scan
        that parsed only part of what it was given.
    """
    rules = _build_rules(findings, inline_explain=inline_explain)
    rule_index = {rule["id"]: idx for idx, rule in enumerate(rules)}

    results = [_finding_to_result(f, rule_index) for f in ReportView(findings).failed]

    if chains:
        chain_rules = _build_chain_rules(chains)
        for cr in chain_rules:
            rule_index[cr["id"]] = len(rules)
            rules.append(cr)
        for chain in chains:
            results.append(_chain_to_result(chain, rule_index))

    payload = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pipeline_check",
                        "version": tool_version or "0.0.0",
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "score": score_result,
                    # ``scan_status`` (when supplied) lets a SARIF
                    # consumer tell a complete scan from one where a file
                    # failed to parse or a cloud module degraded, the same
                    # signal the JSON output and terminal report carry.
                    **({"scan_status": scan_status}
                       if scan_status is not None else {}),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2)


#: Fingerprint version. Bumped only when the hash inputs change in a
#: way that would invalidate every existing GHCS alert. The version
#: name is the dict key SARIF consumers see in
#: ``partialFingerprints``; bumping it produces a new key alongside
#: the old one if/when we ever ship a v2.
_FINGERPRINT_VERSION = "pipelineCheckV1"

#: Cap on the per-file source bytes we read for fingerprint snippets.
#: Generated workflow files can occasionally be large; reading every
#: SARIF emit pass is on the hot path. 256 KB is generous for any
#: real CI/CD config (the largest GitHub workflow files in the wild
#: are <40 KB) and keeps the worst case bounded.
_FINGERPRINT_MAX_FILE_BYTES = 256 * 1024

#: Whitespace normalizer for snippet content. SARIF fingerprints have
#: to survive cosmetic re-indentation (a Prettier run that re-formats
#: YAML must not invalidate every alert), so we collapse runs of
#: whitespace and strip leading/trailing whitespace before hashing.
_WS_RE = re.compile(r"\s+")


def _normalize_path(path: str) -> str:
    """Make path comparison stable across platforms.

    Backslashes -> forward slashes; lowercased on Windows because the
    filesystem itself is case-insensitive there. Repeated runs on the
    same checkout produce the same string regardless of which OS ran
    the scan.
    """
    norm = path.replace("\\", "/")
    norm = norm.lower()
    return norm


def _read_snippet(path: str, line: int | None) -> str:
    """Return a normalized snippet of *path* at *line*, or ``""``.

    Reads *line* from disk if the file exists and is small enough.
    Whitespace is collapsed so a re-indent doesn't invalidate the
    fingerprint. Returns ``""`` for unreadable / out-of-range / non-
    file inputs, callers must treat that as "fingerprint from id +
    path only".
    """
    if not path or line is None or line <= 0:
        return ""
    try:
        if not os.path.isfile(path):
            return ""
        if os.path.getsize(path) > _FINGERPRINT_MAX_FILE_BYTES:
            return ""
        with open(path, encoding="utf-8") as fh:
            for idx, body in enumerate(fh, start=1):
                if idx == line:
                    return _WS_RE.sub(" ", body).strip()
                if idx > line:
                    break
    except (OSError, UnicodeDecodeError):
        return ""
    return ""


def _hash(*parts: str) -> str:
    """SHA-256 of the parts joined by NUL, collision-resistant enough
    for cross-run dedup, short enough that SARIF payloads stay readable."""
    h = hashlib.sha256()
    h.update("\0".join(parts).encode("utf-8"))
    return h.hexdigest()


def _finding_fingerprints(f: Finding) -> dict[str, str]:
    """Build the ``partialFingerprints`` dict for a finding.

    Inputs (in priority order):
      1. ``check_id``, same rule, different rule = different fingerprint.
      2. Normalized path of the primary location (or the resource).
      3. Normalized snippet of the primary location's start line, when
         the file is readable. When the file isn't readable (AWS
         resource, Terraform plan, in-memory test fixture, deleted
         file), the fingerprint falls back to (id, path) only, still
         stable across runs.

    A rule fix that edits the offending line changes the snippet ->
    new fingerprint, so GHCS resolves the prior alert and files a
    fresh one. Editing an unrelated line elsewhere leaves the snippet
    untouched.
    """
    primary: Location | None = f.locations[0] if f.locations else None
    # Only normalize when we have a file-backed location. Non-file
    # resource IDs (AWS ARNs, IAM role names) must pass through
    # untouched. Windows would otherwise lowercase the ARN and
    # produce a different fingerprint than the same scan run on Linux.
    if primary is not None:
        norm_path_or_resource = _normalize_path(primary.path)
    else:
        norm_path_or_resource = f.resource or ""
    snippet = _read_snippet(
        primary.path if primary else "",
        primary.start_line if primary else None,
    )
    digest = _hash(f.check_id, norm_path_or_resource, snippet)
    return {_FINGERPRINT_VERSION: digest}


def _chain_fingerprints(c: Chain) -> dict[str, str]:
    """Build the ``partialFingerprints`` dict for an attack chain.

    Two distinct chain instances on the same chain_id can fire if the
    correlation matched on different resources (e.g. ``group_by_resource``
    chains like AC-009 fire once per workflow). Sorted resources and
    triggering check IDs produce a stable hash per chain instance
    regardless of finding-list order.
    """
    sorted_resources = sorted(c.resources or [])
    sorted_triggers = sorted(c.triggering_check_ids or [])
    digest = _hash(
        c.chain_id,
        "|".join(sorted_resources),
        "|".join(sorted_triggers),
    )
    return {_FINGERPRINT_VERSION: digest}


def _build_chain_rules(chains: list[Chain]) -> list[dict[str, Any]]:
    """Emit one SARIF rule per distinct chain_id."""
    seen: dict[str, dict[str, Any]] = {}
    for c in chains:
        if c.chain_id in seen:
            continue
        level, score = _LEVEL_MAP.get(c.severity, ("error", "8.0"))
        # ``attack-chain`` tag distinguishes correlated multi-finding
        # alerts from individual rule violations in the GitHub UI.
        # MITRE technique IDs are tagged as ``mitre/T<NNNN>``. The
        # 10-tag GitHub cap means ``security`` + ``attack-chain`` +
        # up to 8 MITRE prefixes fit; chains with more techniques
        # still expose the full list via ``properties.mitre_attack``.
        tags = ["security", "attack-chain"]
        for tech in c.mitre_attack[: _MAX_RULE_TAGS - 2]:
            tags.append(f"mitre/{tech}")
        help_md = (
            f"**Summary**\n\n{c.summary}\n\n---\n\n"
            f"**Narrative**\n\n{c.narrative}\n\n---\n\n"
            f"**Recommendation**\n\n{c.recommendation}"
        )
        seen[c.chain_id] = {
            "id": c.chain_id,
            "name": "AttackChain" + c.chain_id.replace("-", ""),
            "shortDescription": {"text": c.title},
            "fullDescription": {"text": c.summary},
            "help": {"text": c.recommendation, "markdown": help_md},
            "defaultConfiguration": {"level": level},
            "properties": {
                "security-severity": score,
                "tags": tags[:_MAX_RULE_TAGS],
                "kill_chain_phase": c.kill_chain_phase,
                "mitre_attack": list(c.mitre_attack),
            },
        }
    return list(seen.values())


def _chain_to_result(chain: Chain, rule_index: dict[str, int]) -> dict[str, Any]:
    """Encode an attack-chain instance as a SARIF result.

    Locations cover every resource the chain spans (workflow files,
    AWS ARNs). Triggering check IDs and finding contexts ride in
    ``properties`` so dashboards can drill from chain → constituent
    findings without re-running the scanner.
    """
    level, _ = _LEVEL_MAP.get(chain.severity, ("error", "8.0"))
    locations = []
    for res in chain.resources or [""]:
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": _artifact_uri(res or "unknown")}
            },
            "logicalLocations": [{"name": res or "unknown", "kind": "resource"}],
        }
        locations.append(loc)
    return {
        "ruleId": chain.chain_id,
        "ruleIndex": rule_index.get(chain.chain_id, 0),
        "level": level,
        "rank": _CONFIDENCE_RANK.get(chain.confidence, 100.0),
        "message": {"text": chain.summary, "markdown": chain.narrative},
        "locations": locations,
        "partialFingerprints": _chain_fingerprints(chain),
        "properties": {
            "severity": chain.severity.value,
            "confidence": chain.confidence.value,
            "kind": "attack-chain",
            "triggering_checks": list(chain.triggering_check_ids),
            "triggering_findings": [
                {"check_id": f.check_id, "resource": f.resource}
                for f in chain.triggering_findings
            ],
            "mitre_attack": list(chain.mitre_attack),
            "kill_chain_phase": chain.kill_chain_phase,
            "references": list(chain.references),
            "confirmed_reachable": chain.confirmed_reachable,
            # Distinguish the proven dataflow tier and the structural-
            # identity tier (both confirmed) from the weaker shared-job
            # co-location fallback so machine consumers can gate on the
            # stronger signals (mirrors --chains-require-dataflow).
            "via_dataflow": chain.via_dataflow,
            "via_structural": chain.via_structural,
            "reachability_note": chain.reachability_note,
        },
    }


# ────────────────────────────────────────────────────────────────────────────
# Internals
# ────────────────────────────────────────────────────────────────────────────


def _build_rules(
    findings: list[Finding], inline_explain: bool = False,
) -> list[dict[str, Any]]:
    """Build one rule per distinct check_id.

    Severity + help text are taken from the first occurrence. Later
    findings with the same check_id reuse the rule; they may differ in
    their per-resource description, which lives on the result, not the
    rule.

    When *inline_explain* is set, the rule's ``exploit_example`` (a
    rule-level property, identical across that rule's findings) is
    appended to both the plain and markdown ``help`` text.
    """
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.check_id in seen:
            continue
        level, score = _LEVEL_MAP.get(f.severity, ("warning", "5.0"))
        # Tags: "security" + the standard slugs this check maps to,
        # priority-ordered so the most user-facing frameworks survive
        # the truncation when the rule maps to more standards than fit.
        # Control IDs are NOT included here. GitHub code-scanning
        # caps tags per rule at 10, and structured control data is
        # already exposed via ``properties.controls`` for programmatic
        # consumers without losing fidelity.
        ordered = _ordered_tags({c.standard for c in f.controls})
        tags = ["security", *ordered][:_MAX_RULE_TAGS]
        rule_props: dict[str, Any] = {
            "security-severity": score,
            "tags": tags,
        }
        if f.cwe:
            rule_props["cwe"] = list(f.cwe)
        # Build richer help markdown
        help_parts = [f"**Recommendation**\n\n{f.recommendation}"]
        if f.cwe:
            help_parts.append(f"**CWE:** {', '.join(f.cwe)}")
        # ``--inline-explain`` appends the proof-of-exploit snippet to
        # the rule help so GitHub code-scanning's rule pane carries it.
        help_text = f.recommendation or f.title
        exploit = inline_exploit(f, inline_explain)
        if exploit:
            fence = markdown_code_fence(exploit)
            help_parts.append(
                f"**Proof of exploit**\n\n{fence}\n{exploit}\n{fence}"
            )
            help_text = f"{help_text}\n\nProof of exploit:\n{exploit}"
        help_md = "\n\n---\n\n".join(help_parts)

        seen[f.check_id] = {
            "id": f.check_id,
            "name": _rule_name(f.check_id, f.title),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.recommendation or f.title},
            "help": {
                "text": help_text,
                "markdown": help_md,
            },
            "defaultConfiguration": {"level": level},
            "properties": rule_props,
        }
    return list(seen.values())


def _finding_to_result(f: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    level, _ = _LEVEL_MAP.get(f.severity, ("warning", "5.0"))
    logical_location: dict[str, Any] = {"name": f.resource, "kind": "resource"}
    # AWS resources: surface an ARN/region property so programmatic
    # SARIF consumers can pivot to the console.
    arn = _aws_arn(f.resource)
    if arn:
        logical_location["fullyQualifiedName"] = arn

    properties: dict[str, Any] = {
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "controls": [c.to_dict() for c in f.controls],
    }
    if f.cwe:
        properties["cwe"] = list(f.cwe)
    if arn:
        properties["arn"] = arn
        properties["region"] = _region_from_arn(arn) or ""

    # Prefer the rule-supplied structured locations when present.
    # ``Finding.locations`` is the canonical source: each entry maps
    # to one SARIF ``locations[]`` entry with a real ``region``. When
    # absent (AWS / Terraform / CFN, or rules not yet retrofitted),
    # fall back to the legacy single-location + ``_best_effort_line``
    # path so we don't regress those providers.
    locations: list[dict[str, Any]] = []
    if f.locations:
        for loc in f.locations:
            phys: dict[str, Any] = {
                "artifactLocation": {"uri": _artifact_uri(loc.path)},
            }
            # SARIF anchors a region on ``startLine``: ``startColumn`` is
            # defined relative to it, and ``endLine`` / ``endColumn``
            # without it produce an invalid region that GitHub code
            # scanning rejects. Only emit the column/end fields when a
            # start line is known; otherwise fall back to a file-level
            # location (no region).
            region: dict[str, Any] = {}
            if loc.start_line is not None:
                region["startLine"] = loc.start_line
                if loc.end_line is not None and loc.end_line != loc.start_line:
                    region["endLine"] = loc.end_line
                if loc.start_column is not None:
                    region["startColumn"] = loc.start_column
                if loc.end_column is not None:
                    region["endColumn"] = loc.end_column
            if region:
                phys["region"] = region
            locations.append({
                "physicalLocation": phys,
                "logicalLocations": [logical_location],
            })
    else:
        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": _artifact_uri(f.resource)},
        }
        start_line = _best_effort_line(f)
        if start_line is not None:
            physical_location["region"] = {"startLine": start_line}
        locations.append({
            "physicalLocation": physical_location,
            "logicalLocations": [logical_location],
        })

    # SARIF ``rank`` (0–100 float) lets GitHub/GitLab Code Scanning
    # sort results by how much the scanner trusts them, orthogonal
    # to severity. HIGH-confidence findings surface first; LOW are
    # de-ranked so noisy rules don't drown out the signal.
    # SARIF 2.1.0 defines ``rank`` on ``reportingDescriptor``, not on
    # ``result`` (which sets ``additionalProperties: false``). Carry it
    # in ``properties`` so strict validators accept the output.
    properties["rank"] = _CONFIDENCE_RANK.get(f.confidence, 100.0)

    result: dict[str, Any] = {
        "ruleId": f.check_id,
        "ruleIndex": rule_index.get(f.check_id, 0),
        "level": level,
        # SARIF 2.1.0 requires message.text to be a string; fall back to
        # the title so an empty description can't emit ``"text": null``
        # (every sibling reporter guards this the same way).
        "message": {"text": f.description or f.title},
        "locations": locations,
        # ``partialFingerprints`` lets GHCS / GitLab / Azure DevOps
        # match the same finding across runs so an unchanged repo
        # doesn't re-alert on every push.
        "partialFingerprints": _finding_fingerprints(f),
        "properties": properties,
    }
    return result


def _best_effort_line(f: Finding) -> int | None:
    """Try to find a line number in ``f.resource`` the finding refers to.

    Strategy: only run on file-based findings (resource looks like a
    path, file exists, is small enough to read). Match by check_id —
    e.g. GHA-001 looks for a tag-pinned ``uses:`` line, GHA-008 looks
    for a credential-shaped token. When no pattern matches we return
    None so the SARIF consumer falls back to whole-file annotation.
    """
    import os
    import re as _re

    from .checks._patterns import SECRET_VALUE_RE

    path = f.resource
    if not path or not isinstance(path, str):
        return None
    # Avoid pathologically large files and AWS resource names.
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > 256 * 1024:
            return None
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return None

    check_id = f.check_id.upper()
    # Per-check line signatures. Return the 1-based line number of the
    # first match. Missing patterns mean "don't annotate a specific
    # line", caller falls back to file-level.
    patterns: dict[str, _re.Pattern[str]] = {
        "GHA-001": _re.compile(r"\buses:\s*\S+@(?!\s*[0-9a-f]{40}\b)\S+"),
        "GHA-002": _re.compile(r"pull_request\.head\.(?:sha|ref)"),
        "GHA-003": _re.compile(r"\$\{\{\s*github\.event\."),
        "GL-001":  _re.compile(r"^\s*image:\s*\S+(?<!@sha256):\w+"),
        "BB-001":  _re.compile(r"^\s*-?\s*pipe:\s*\S+"),
        "ADO-001": _re.compile(r"^\s*-?\s*task:\s*\S+@\d"),
        "ADO-005": _re.compile(r"^\s*image:\s*\S+:\S+"),
        "JF-001":  _re.compile(r"@Library\("),
        "JF-002":  _re.compile(r'(?:sh|bat)\s*(?:\(?\s*".*\$(?:BRANCH_NAME|CHANGE_))'),
        "JF-003":  _re.compile(r"\bagent\s+any\b"),
        "JF-019":  _re.compile(r"Runtime\.getRuntime|Class\.forName|@Grab\b"),
        "CC-001":  _re.compile(r"^\s*\w[\w-]*:\s*\S+@(?!v?\d+\.\d+\.\d+)"),
        "CC-002":  _re.compile(r"\$CIRCLE_BRANCH|\$CIRCLE_TAG"),
        # Per-provider entries for the cross-provider shell_eval
        # primitive: best-effort line match on ``eval`` / ``sh -c``
        # followed by a variable or command-substitution.
        "GHA-028": _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        "GL-026":  _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        "BB-026":  _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        "ADO-027": _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        "CC-027":  _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        "JF-030":  _re.compile(r"\beval\s+[\"'$]|\b(?:ba)?sh\s+-c\s+[\"'$]"),
        # Per-provider entries for the lockfile_integrity primitive:
        # best-effort line match on unpinned git URLs or integrity-
        # bypassing local-path / tarball installs.
        "GHA-029": _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
        "GL-027":  _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
        "BB-027":  _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
        "ADO-028": _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
        "CC-028":  _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
        "JF-031":  _re.compile(r"\bgit\+[a-z]+://|(?:pip3?|npm|yarn)\s+(?:install|add)\s+(?:-e\s+)?(?:\./|/[A-Za-z]|file:|https?://\S+\.(?:whl|tgz|tar\.gz))"),
    }
    pat = patterns.get(check_id)
    if pat is not None:
        for idx, line in enumerate(lines, start=1):
            if pat.search(line):
                return idx
        return None

    # Generic fallback for secret-scanning checks: first line matching
    # the built-in credential regex.
    if check_id in ("GHA-008", "GL-008", "BB-008", "ADO-008", "JF-008", "CC-008"):
        for idx, line in enumerate(lines, start=1):
            if SECRET_VALUE_RE.search(line):
                return idx
            # SECRET_VALUE_RE is anchored; also check for AKIA inline.
            if "AKIA" in line or "ghp_" in line:
                return idx
    return None


def _aws_arn(resource: str) -> str | None:
    """Return the ARN embedded in an AWS check resource, or None."""
    if isinstance(resource, str) and resource.startswith("arn:"):
        return resource
    return None


def _region_from_arn(arn: str) -> str | None:
    # arn:aws:service:region:account:resource
    try:
        parts = arn.split(":", 5)
        return parts[3] or None
    except (IndexError, AttributeError):
        return None


def _rule_name(check_id: str, title: str) -> str:
    """Derive a CamelCase SARIF rule name from the title.

    SARIF requires ``name`` to be a *stable* identifier distinct from
    ``id``. We build it from the title by stripping non-alphanumerics and
    camel-casing. This is stable as long as titles don't change and is
    readable in UIs that show rule names.
    """
    parts = [p for p in _split_title(title) if p]
    if not parts:
        return check_id.replace("-", "")
    return "".join(p[:1].upper() + p[1:].lower() for p in parts)


def _split_title(title: str) -> list[str]:
    # Splits on any non-alphanumeric; empty segments are dropped downstream.
    out: list[str] = []
    cur: list[str] = []
    for ch in title:
        if ch.isalnum():
            cur.append(ch)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    return out


def _artifact_uri(resource: str) -> str:
    """Best-effort mapping from a finding's resource handle to a SARIF URI.

    For file-based providers (GitHub / GitLab / Bitbucket) the resource
    is already a path. For AWS / Terraform it is a resource name (e.g.
    an ARN or bucket name). We encode those as ``resource://<name>`` so
    SARIF consumers treat them as opaque identifiers rather than trying
    to open a file on disk.
    """
    if not resource:
        return "unknown"
    lowered = resource.lower()
    _file_exts = (
        ".yml", ".yaml", ".tf", ".json", ".xml", ".toml", ".txt",
        ".cfg", ".config", ".csproj", ".props", ".lock", ".npmrc",
    )
    _bare_names = {
        "dockerfile", "containerfile", "jenkinsfile", "makefile",
        "gemfile", "rakefile", "vagrantfile",
    }
    if (
        "/" in resource
        or "\\" in resource
        or lowered.endswith(_file_exts)
        or lowered in _bare_names
        or lowered.startswith(("dockerfile", "containerfile"))
    ):
        return urllib.parse.quote(resource.replace("\\", "/"), safe="/")
    return f"resource:///{resource}"
