"""Factory for the YAML-blob rule shape shared across providers.

Several rule families exist as near-verbatim wrappers around a shared
detection primitive: each provider lowercases the parsed YAML body,
calls the scanner, and assembles a ``Finding`` from the result. The
factory collapses that boilerplate so per-provider rule modules carry
only their unique metadata (id, title, prose, severity).

Targets the ``check(path, doc) -> Finding`` shape. Rules that need
step-level ``Location`` anchors (GHA-017), container-flavored gates
(DR-006), step iteration (BK-008), or Jenkinsfile-text inputs
(JF-* clones) keep their bespoke check bodies because their carve-outs
don't fit the blob template.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from ..base import Finding, blob_lower
from ..rule import Rule

T = TypeVar("T")


def yaml_blob_check(
    rule: Rule,
    *,
    scanner: Callable[[str], T],
    pass_desc: str,
    fail_desc: Callable[[T], str],
    pass_recommendation: str | None = None,
) -> Callable[[str, dict[str, Any]], Finding]:
    """Build a ``check(path, doc)`` callable for the blob-scan rule shape.

    Lowers ``doc`` via :func:`blob_lower`, runs ``scanner`` against the
    result, and builds a :class:`Finding` with the rule's metadata.
    ``pass_desc`` fires when ``scanner`` returns falsy;
    ``fail_desc(result)`` fires on a truthy result. The recommendation
    field is sourced from ``rule.recommendation`` unless
    ``pass_recommendation`` is supplied, in which case the override
    fires on the passing branch only (used by malicious-activity
    rules that print "No action required." when clean).
    """

    def check(path: str, doc: dict[str, Any]) -> Finding:
        result = scanner(blob_lower(doc))
        passed = not result
        if passed and pass_recommendation is not None:
            recommendation = pass_recommendation
        else:
            recommendation = rule.recommendation
        return Finding(
            check_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            resource=path,
            description=pass_desc if passed else fail_desc(result),
            recommendation=recommendation,
            passed=passed,
        )

    return check
