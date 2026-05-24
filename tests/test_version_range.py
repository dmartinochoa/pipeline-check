"""Tests for the GHSA version range matcher primitive."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._primitives.version_range import (
    any_range_matches,
    parse_version,
    version_in_range,
)


class TestParseVersion:
    def test_simple_semver(self):
        assert parse_version("4.2.1") == (4, 2, 1)

    def test_v_prefix(self):
        assert parse_version("v4.2.1") == (4, 2, 1)

    def test_major_minor(self):
        assert parse_version("4.2") == (4, 2)

    def test_major_only(self):
        assert parse_version("4") == (4,)

    def test_v_prefix_major_only(self):
        assert parse_version("v4") == (4,)

    def test_non_version(self):
        assert parse_version("not-a-version") is None

    def test_sha_not_a_version(self):
        assert parse_version("abcdef1234567890abcdef1234567890abcdef12") is None

    def test_whitespace_stripped(self):
        assert parse_version("  v4.2.1  ") == (4, 2, 1)


class TestVersionInRange:
    def test_below_upper_bound(self):
        assert version_in_range("4.1.6", "< 4.1.7") is True

    def test_at_upper_bound(self):
        assert version_in_range("4.1.7", "< 4.1.7") is False

    def test_above_upper_bound(self):
        assert version_in_range("4.1.8", "< 4.1.7") is False

    def test_in_bounded_range(self):
        assert version_in_range("3.2.0", ">= 3.0.0, < 3.5.1") is True

    def test_at_lower_bound(self):
        assert version_in_range("3.0.0", ">= 3.0.0, < 3.5.1") is True

    def test_below_lower_bound(self):
        assert version_in_range("2.9.9", ">= 3.0.0, < 3.5.1") is False

    def test_at_upper_bound_exclusive(self):
        assert version_in_range("3.5.1", ">= 3.0.0, < 3.5.1") is False

    def test_exact_match(self):
        assert version_in_range("4.2.1", "= 4.2.1") is True

    def test_exact_no_match(self):
        assert version_in_range("4.2.2", "= 4.2.1") is False

    def test_v_prefix_in_version(self):
        assert version_in_range("v4.1.6", "< 4.1.7") is True

    def test_v_prefix_in_range(self):
        assert version_in_range("4.1.6", "< v4.1.7") is True

    def test_unparseable_version(self):
        assert version_in_range("main", "< 4.1.7") is None

    def test_unparseable_range(self):
        assert version_in_range("4.1.6", "not a range") is None

    def test_lte_at_bound(self):
        assert version_in_range("4.1.7", "<= 4.1.7") is True

    def test_lte_above_bound(self):
        assert version_in_range("4.1.8", "<= 4.1.7") is False

    def test_gt_at_bound(self):
        assert version_in_range("4.1.7", "> 4.1.7") is False

    def test_gt_above_bound(self):
        assert version_in_range("4.1.8", "> 4.1.7") is True

    def test_padding_short_version(self):
        assert version_in_range("4.1", "< 4.1.7") is True

    def test_padding_exact(self):
        assert version_in_range("4.1", "= 4.1.0") is True


class TestAnyRangeMatches:
    def test_matches_one_of_many(self):
        matched, hits = any_range_matches(
            "3.2.0", [">= 1.0.0, < 2.0.0", ">= 3.0.0, < 4.0.0"],
        )
        assert matched
        assert len(hits) == 1
        assert ">= 3.0.0, < 4.0.0" in hits

    def test_matches_none(self):
        matched, hits = any_range_matches(
            "5.0.0", [">= 1.0.0, < 2.0.0", ">= 3.0.0, < 4.0.0"],
        )
        assert not matched
        assert hits == []

    def test_unparseable_range_skipped(self):
        matched, hits = any_range_matches(
            "3.2.0", ["not a range", ">= 3.0.0, < 4.0.0"],
        )
        assert matched
        assert len(hits) == 1
