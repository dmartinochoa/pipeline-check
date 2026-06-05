"""Shared derivation of the facts every reporter needs from a finding set.

Each reporter answers the same questions about a scan's findings: which
failed, which passed, the canonical display order, and the pass/fail
counts. Those were re-derived inline in each reporter, which let the
ordering drift between formats (the terminal and markdown reports sorted
by ``(passed, -severity, check_id)``; an ad-hoc copy elsewhere could
drop the ``check_id`` tiebreak and render findings in a non-deterministic
order). Centralizing them here keeps every output format consistent and
gives one place to change report-wide ordering policy.

The two sort-key helpers are the contract: ``report_sort_key`` is the
full-report order (failures first), ``failure_sort_key`` is the
failures-only order. ``ReportView`` bundles the partitions and counts.
"""
from __future__ import annotations

from dataclasses import dataclass

from .checks.base import Finding, severity_rank


def report_sort_key(f: Finding) -> tuple[bool, int, str]:
    """Canonical full-report order.

    Failures sort before passes (``False`` < ``True``), then by
    descending severity, then ``check_id`` for a stable, deterministic
    order across runs.
    """
    return (f.passed, -severity_rank(f.severity), f.check_id)


def failure_sort_key(f: Finding) -> tuple[int, str]:
    """Failures-only order: descending severity, then ``check_id``."""
    return (-severity_rank(f.severity), f.check_id)


@dataclass(frozen=True)
class ReportView:
    """A normalized view of a finding set for reporters.

    ``findings`` is the raw set as the scanner produced it; everything
    else is derived. Build one per report and read the partitions /
    counts instead of re-deriving them. ``failed`` preserves input order
    (the order the scanner emitted, which reporters that don't re-sort
    rely on); ``ordered`` is the canonical display order.
    """

    findings: list[Finding]

    @property
    def failed(self) -> list[Finding]:
        """Failing findings in input order (no re-sort)."""
        return [f for f in self.findings if not f.passed]

    @property
    def passed(self) -> list[Finding]:
        """Passing findings in input order."""
        return [f for f in self.findings if f.passed]

    @property
    def ordered(self) -> list[Finding]:
        """Every finding in canonical report order (failures first)."""
        return sorted(self.findings, key=report_sort_key)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def failed_count(self) -> int:
        return sum(1 for f in self.findings if not f.passed)

    @property
    def passed_count(self) -> int:
        return self.total - self.failed_count
