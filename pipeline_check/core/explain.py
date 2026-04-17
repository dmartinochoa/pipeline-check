"""Per-check reference renderer — the body of ``pipeline_check explain``.

``--help`` lists every flag; ``--man TOPIC`` is the narrative per
subsystem; ``explain CHECK-ID`` is the narrative per check. The three
are orthogonal: when a finding fires in CI and the engineer wants to
know *why this specific rule* and *how to fix it*, they reach for
``explain`` rather than source-diving ``docs/providers/<provider>.md``
or the rule module.

The renderer accepts a rule-based ``Rule`` directly when the provider
has one, and falls back to a docstring-parsed stub for class-based
modules (AWS core services, Terraform core) where only ``id`` /
``title`` / ``severity`` are recoverable without running the check.

Output is plain text — no ANSI, no rich markup — so it reads the same
through ``less``, piped to a file, or copy-pasted into a PR comment.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import sys
from dataclasses import dataclass

from .checks._confidence import confidence_for
from .checks.base import Severity
from .checks.rule import Rule, discover_rules
from .standards import resolve_for_check


@dataclass(frozen=True)
class _CheckMeta:
    """Everything ``explain`` needs to render a check — either derived
    from a ``Rule`` or from a class-based module's docstring."""

    id: str
    title: str
    severity: Severity
    source: str  # "rule" or "class"
    rule: Rule | None = None
    docstring: str = ""


# Rule-based packages: ``Rule`` metadata fully populated.
_RULE_PACKAGES: tuple[str, ...] = (
    "pipeline_check.core.checks.github.rules",
    "pipeline_check.core.checks.gitlab.rules",
    "pipeline_check.core.checks.bitbucket.rules",
    "pipeline_check.core.checks.azure.rules",
    "pipeline_check.core.checks.jenkins.rules",
    "pipeline_check.core.checks.circleci.rules",
    "pipeline_check.core.checks.aws.rules",
)

# Class-based packages: ID/TITLE/SEV recoverable via docstring table.
_CLASS_PACKAGES: tuple[str, ...] = (
    "pipeline_check.core.checks.aws",
    "pipeline_check.core.checks.terraform",
    "pipeline_check.core.checks.cloudformation",
)

# Matches a row in the class-based module docstring table:
#     CB-001  Secrets in plaintext environment variables      CRITICAL  ...
_ROW_RE = re.compile(
    r"^\s*(?P<id>[A-Z]+-\d+)\s{2,}(?P<title>.+?)\s{2,}"
    r"(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
    re.MULTILINE,
)


_CACHE: dict[str, _CheckMeta] | None = None


def _build_index() -> dict[str, _CheckMeta]:
    """Discover every known check ID and return ID → _CheckMeta.

    Cached after the first call. Rule-based providers win when an ID
    appears in both (e.g. a class-based module that has since been
    migrated to a rule — the newer Rule wins).
    """
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    index: dict[str, _CheckMeta] = {}

    # Class-based first — rule-based registrations below overwrite.
    for class_pkg_name in _CLASS_PACKAGES:
        try:
            pkg = importlib.import_module(class_pkg_name)
        except Exception:  # pragma: no cover - defensive
            continue
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_") or info.name == "rules":
                continue
            try:
                mod = importlib.import_module(f"{class_pkg_name}.{info.name}")
            except Exception:
                continue
            doc = mod.__doc__ or ""
            for m in _ROW_RE.finditer(doc):
                cid = m["id"]
                try:
                    sev = Severity(m["sev"])
                except ValueError:
                    continue
                index[cid] = _CheckMeta(
                    id=cid,
                    title=m["title"].strip(),
                    severity=sev,
                    source="class",
                    docstring=doc,
                )

    # Rule-based — definitive for any ID they cover.
    for pkg_fqn in _RULE_PACKAGES:
        try:
            for rule, _check in discover_rules(pkg_fqn):
                index[rule.id] = _CheckMeta(
                    id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    source="rule",
                    rule=rule,
                )
        except Exception:  # pragma: no cover - defensive
            continue

    _CACHE = index
    return index


def available_ids() -> list[str]:
    """Every check ID this scanner knows about, sorted."""
    return sorted(_build_index())


def _suggest(unknown: str, ids: list[str], limit: int = 5) -> list[str]:
    """Offer near-matches for an unknown ID — prefix match wins over
    fuzzy so ``GHA-100`` suggests ``GHA-001 … GHA-099`` first."""
    u = unknown.upper()
    # Same prefix (e.g. "GHA-") first.
    dash = u.find("-")
    prefix = u[: dash + 1] if dash > 0 else ""
    prefix_hits = [i for i in ids if prefix and i.startswith(prefix)][:limit]
    if prefix_hits:
        return prefix_hits
    # Fallback: substring match.
    return [i for i in ids if u in i][:limit]


def render(check_id: str) -> tuple[str, int]:
    """Render the explain body for *check_id*.

    Returns ``(text, exit_code)``. Unknown IDs render a suggestion
    list and return exit code 3 so shell scripts can detect typos.
    """
    cid = check_id.strip().upper()
    index = _build_index()
    meta = index.get(cid)
    if meta is None:
        ids = available_ids()
        suggestions = _suggest(cid, ids)
        lines = [f"Unknown check ID: {check_id!r}.", ""]
        if suggestions:
            lines.append("Did you mean:")
            for s in suggestions:
                lines.append(f"  {s}  {index[s].title}")
            lines.append("")
        lines.append(
            "Run ``pipeline_check --pipeline <provider> --list-checks`` "
            "to see all IDs for a provider, or ``pipeline_check "
            "--man`` for the manual index."
        )
        return "\n".join(lines) + "\n", 3

    return _render_meta(meta), 0


def _render_meta(meta: _CheckMeta) -> str:
    """Plain-text body for one check."""
    lines: list[str] = []
    confidence = confidence_for(meta.id)

    header = (
        f"{meta.id}  ·  {meta.severity.value}  ·  {confidence.value} confidence"
    )
    lines.append(header)
    lines.append(meta.title)
    lines.append("")

    # Compliance cross-references, grouped by standard.
    refs = resolve_for_check(meta.id)
    if refs:
        by_std: dict[str, list[str]] = {}
        std_titles: dict[str, str] = {}
        for r in refs:
            by_std.setdefault(r.standard, []).append(r.control_id)
            std_titles[r.standard] = r.standard_title
        col_width = max(len(s) for s in by_std) + 2
        for std in sorted(by_std):
            ctrls = ", ".join(sorted(set(by_std[std])))
            lines.append(f"  {std:<{col_width}}{ctrls}")
        lines.append("")

    # Rule-based content — the fully-populated path.
    if meta.source == "rule" and meta.rule is not None:
        rule = meta.rule
        if rule.cwe:
            lines.append(f"  CWE: {', '.join(rule.cwe)}")
            lines.append("")
        if rule.docs_note:
            lines.append("[What it checks]")
            for para in rule.docs_note.strip().splitlines():
                lines.append(f"  {para}" if para else "")
            lines.append("")
        if rule.known_fp:
            lines.append("[Known false-positive modes]")
            for mode in rule.known_fp:
                lines.append(f"  * {mode}")
            lines.append("")
        if rule.recommendation:
            lines.append("[How to fix]")
            for para in rule.recommendation.strip().splitlines():
                lines.append(f"  {para}" if para else "")
            lines.append("")
    else:
        # Class-based fallback — the docstring table we matched the
        # row from is the most reliable thing we have.
        lines.append("[What it checks]")
        lines.append(
            "  Reference implementation lives in a class-based check "
            "module; run the scanner to see the exact resource match "
            "or consult the provider reference doc."
        )
        lines.append("")

    # Cross-references surfaced at the end so the body stays skimmable.
    lines.append("[See also]")
    lines.append(
        "  pipeline_check --pipeline <provider> --list-checks  "
        "(every check for the provider)"
    )
    lines.append("  pipeline_check --man                             "
                 "(manual topic index)")

    return "\n".join(lines) + "\n"


def print_explain(check_id: str) -> int:
    """CLI entry point — print and return the exit code."""
    body, code = render(check_id)
    sys.stdout.write(body)
    return code
