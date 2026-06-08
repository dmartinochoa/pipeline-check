"""JUnit XML reporter.

JUnit is the de-facto interchange format for test results across CI
systems. Jenkins, GitLab CI, Azure DevOps, CircleCI, Buildkite, and
GitHub Actions all parse it natively and render each finding as a
pass/fail row in the build UI with no plugin configuration. Emitting
JUnit turns pipeline_check findings into first-class CI test results.

Shape:

- One ``<testsuites>`` root with aggregate counts (tests / failures).
- One ``<testsuite>`` per check-ID *prefix* (e.g. GHA, IAM, CB) so CI
  UIs surface a "GitHub Actions rules: 3/12 failing" row rather than
  a single opaque suite. Groupings match how the provider docs
  organize rules, so users already know how to navigate them. Each
  suite leads with a ``<properties>`` block carrying the run's
  ``pipeline-check.grade`` and ``pipeline-check.score`` (the standard,
  portable slot for that metadata; ``data-*`` attributes are not JUnit).
- One ``<testcase>`` per Finding. Passing findings are empty self-
  closed elements. Failing findings nest a ``<failure>`` child whose
  ``message`` is the one-line description, ``type`` is the severity
  (CRITICAL/HIGH/MEDIUM/LOW), and body carries the full recommendation
  + compliance controls for inline display.

Escaping uses ``xml.sax.saxutils`` so angle brackets / ampersands in
user-facing text (e.g. a shell snippet in a description) can't break
the XML envelope.
"""
from __future__ import annotations

import re
from xml.sax.saxutils import escape as _sax_escape
from xml.sax.saxutils import quoteattr as _sax_quoteattr

from .checks.base import Finding, inline_exploit
from .report_view import ReportView
from .scorer import ScoreResult

# XML 1.0 forbids the C0 control characters except tab / LF / CR.
# ``saxutils`` escapes markup but passes these bytes through verbatim,
# so a finding field carrying one (a NUL or other control byte lifted
# from a scanned file) yields non-well-formed XML that CI ingestors
# reject. Strip them before escaping.
_XML_INVALID_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xml_escape(text: str) -> str:
    return _sax_escape(_XML_INVALID_RE.sub("", text))


def _xml_attr(text: str) -> str:
    return _sax_quoteattr(_XML_INVALID_RE.sub("", text))


def _prefix(check_id: str) -> str:
    """Derive a suite name from a check_id, the letters before the first dash.

    ``IAM-001`` → ``IAM``, ``GHA-028`` → ``GHA``, ``SIGN-001`` → ``SIGN``.
    Falls back to the full ID if there's no dash.
    """
    dash = check_id.find("-")
    return check_id[:dash] if dash > 0 else check_id


def _failure_body(f: Finding, inline_explain: bool = False) -> str:
    """Render the body of a <failure> element, recommendation + controls."""
    parts = [f.description.strip()] if f.description else []
    if f.recommendation:
        parts.append(f"Recommendation: {f.recommendation.strip()}")
    if f.cwe:
        parts.append(f"CWE: {', '.join(f.cwe)}")
    if f.controls:
        parts.append(
            "Controls: " + "; ".join(
                f"{c.standard}:{c.control_id}" for c in f.controls
            )
        )
    exploit = inline_exploit(f, inline_explain)
    if exploit:
        parts.append(f"Proof of exploit:\n{exploit}")
    return "\n".join(parts)


def report_junit(
    findings: list[Finding],
    score_result: ScoreResult,
    inline_explain: bool = False,
) -> str:
    """Render *findings* as a JUnit XML 4.x report string.

    Returns the XML as a string, prologue included. The caller decides
    whether to write to a file or stdout, symmetric with the other
    reporters in this package. When *inline_explain* is set, each
    failing finding's ``exploit_example`` is appended to its
    ``<failure>`` body.
    """
    # Group by prefix. Preserve input order within each group so that
    # CI UIs don't shuffle the user's mental ordering.
    by_suite: dict[str, list[Finding]] = {}
    for f in findings:
        by_suite.setdefault(_prefix(f.check_id), []).append(f)

    view = ReportView(findings)
    total = view.total
    failures = view.failed_count
    grade = score_result.get("grade", "")
    score = f"{score_result.get('score', 0)}"

    out: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    out.append(
        f'<testsuites name="pipeline_check" '
        f'tests="{total}" failures="{failures}" errors="0">'
    )
    for suite, group in sorted(by_suite.items()):
        suite_total = len(group)
        suite_failed = sum(1 for f in group if not f.passed)
        out.append(
            f'  <testsuite name={_xml_attr(suite)} '
            f'tests="{suite_total}" failures="{suite_failed}" errors="0">'
        )
        # Carry the run-level grade / score as standard JUnit
        # ``<properties>`` rather than non-standard ``data-*`` attributes
        # on the root. ``data-*`` is an HTML convention, not JUnit, and
        # strict schema-validating ingestors (some Azure DevOps / Jenkins
        # publishers) reject unknown attributes; ``<properties>`` is the
        # portable extension slot and must precede the test cases.
        out.append('    <properties>')
        out.append(
            f'      <property name="pipeline-check.grade" '
            f'value={_xml_attr(grade)} />'
        )
        out.append(
            f'      <property name="pipeline-check.score" '
            f'value={_xml_attr(score)} />'
        )
        out.append('    </properties>')
        for f in group:
            # JUnit's <testcase> uses ``name`` for the displayed label
            # and ``classname`` for the grouping-within-suite. We put
            # the title in name (human-readable) and the check_id in
            # classname (stable identifier CI tools dedupe on).
            name = _xml_attr(f.title)
            classname = _xml_attr(f.check_id)
            resource = _xml_attr(f.resource or "")
            # ``time="0"`` is required by JUnit 4 / surefire schemas
            # even when the runner doesn't measure per-finding time.
            # Some CI ingestors reject testcase elements without it.
            if f.passed:
                out.append(
                    f'    <testcase name={name} classname={classname} '
                    f'file={resource} time="0" />'
                )
            else:
                body = _xml_escape(_failure_body(f, inline_explain))
                msg = _xml_attr(
                    (f.description or f.title).split("\n", 1)[0][:200]
                )
                typ = _xml_attr(f.severity.value)
                out.append(
                    f'    <testcase name={name} classname={classname} '
                    f'file={resource} time="0">'
                )
                out.append(
                    f'      <failure message={msg} type={typ}>{body}</failure>'
                )
                out.append('    </testcase>')
        out.append('  </testsuite>')
    out.append('</testsuites>')
    return "\n".join(out) + "\n"
