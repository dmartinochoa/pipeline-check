"""JUnit XML reporter.

JUnit is the de-facto interchange format for test results across CI
systems — Jenkins, GitLab CI, Azure DevOps, CircleCI, Buildkite, and
GitHub Actions all parse it natively and render each finding as a
pass/fail row in the build UI with no plugin configuration. Emitting
JUnit turns pipeline_check findings into first-class CI test results.

Shape:

- One ``<testsuites>`` root with aggregate counts (tests / failures).
- One ``<testsuite>`` per check-ID *prefix* (e.g. GHA, IAM, CB) so CI
  UIs surface a "GitHub Actions rules: 3/12 failing" row rather than
  a single opaque suite. Groupings match how the provider docs
  organize rules, so users already know how to navigate them.
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

from xml.sax.saxutils import escape as _xml_escape
from xml.sax.saxutils import quoteattr as _xml_attr

from .checks.base import Finding


def _prefix(check_id: str) -> str:
    """Derive a suite name from a check_id — the letters before the first dash.

    ``IAM-001`` → ``IAM``, ``GHA-028`` → ``GHA``, ``SIGN-001`` → ``SIGN``.
    Falls back to the full ID if there's no dash.
    """
    dash = check_id.find("-")
    return check_id[:dash] if dash > 0 else check_id


def _failure_body(f: Finding) -> str:
    """Render the body of a <failure> element — recommendation + controls."""
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
    return "\n".join(parts)


def report_junit(findings: list[Finding], score_result: dict) -> str:
    """Render *findings* as a JUnit XML 4.x report string.

    Returns the XML as a string, prologue included. The caller decides
    whether to write to a file or stdout — symmetric with the other
    reporters in this package.
    """
    # Group by prefix. Preserve input order within each group so that
    # CI UIs don't shuffle the user's mental ordering.
    by_suite: dict[str, list[Finding]] = {}
    for f in findings:
        by_suite.setdefault(_prefix(f.check_id), []).append(f)

    total = len(findings)
    failures = sum(1 for f in findings if not f.passed)
    grade = score_result.get("grade", "")
    score = f"{score_result.get('total', 0)}"

    out: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    out.append(
        f'<testsuites name="pipeline_check" '
        f'tests="{total}" failures="{failures}" errors="0" '
        f'data-grade={_xml_attr(grade)} data-score={_xml_attr(score)}>'
    )
    for suite, group in sorted(by_suite.items()):
        suite_total = len(group)
        suite_failed = sum(1 for f in group if not f.passed)
        out.append(
            f'  <testsuite name={_xml_attr(suite)} '
            f'tests="{suite_total}" failures="{suite_failed}" errors="0">'
        )
        for f in group:
            # JUnit's <testcase> uses ``name`` for the displayed label
            # and ``classname`` for the grouping-within-suite. We put
            # the title in name (human-readable) and the check_id in
            # classname (stable identifier CI tools dedupe on).
            name = _xml_attr(f.title)
            classname = _xml_attr(f.check_id)
            resource = _xml_attr(f.resource or "")
            if f.passed:
                out.append(
                    f'    <testcase name={name} classname={classname} '
                    f'file={resource} />'
                )
            else:
                body = _xml_escape(_failure_body(f))
                msg = _xml_attr(
                    (f.description or f.title).split("\n", 1)[0][:200]
                )
                typ = _xml_attr(f.severity.value)
                out.append(
                    f'    <testcase name={name} classname={classname} '
                    f'file={resource}>'
                )
                out.append(
                    f'      <failure message={msg} type={typ}>{body}</failure>'
                )
                out.append('    </testcase>')
        out.append('  </testsuite>')
    out.append('</testsuites>')
    return "\n".join(out) + "\n"
