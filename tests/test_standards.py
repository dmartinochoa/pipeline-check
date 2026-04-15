"""Tests for the compliance standards registry and built-in standards."""

import pytest

from pipeline_check.core import standards
from pipeline_check.core.standards.base import ControlRef, Standard


class TestRegistry:
    def test_both_builtin_standards_registered(self):
        names = standards.available()
        assert "owasp_cicd_top_10" in names
        assert "cis_aws_foundations" in names

    def test_get_returns_standard(self):
        std = standards.get("cis_aws_foundations")
        assert isinstance(std, Standard)
        assert std.name == "cis_aws_foundations"

    def test_get_is_case_insensitive(self):
        assert standards.get("CIS_AWS_FOUNDATIONS") is not None

    def test_get_unknown_returns_none(self):
        assert standards.get("nope") is None

    def test_resolve_all_when_none(self):
        resolved = standards.resolve(None)
        assert {s.name for s in resolved} == set(standards.available())

    def test_resolve_subset(self):
        resolved = standards.resolve(["cis_aws_foundations"])
        assert [s.name for s in resolved] == ["cis_aws_foundations"]

    def test_resolve_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown standard"):
            standards.resolve(["does_not_exist"])


class TestStandardIntegrity:
    """Catch typos: every control_id referenced in mappings must be defined."""

    @pytest.mark.parametrize("name", ["owasp_cicd_top_10", "cis_aws_foundations"])
    def test_every_mapped_control_is_defined(self, name):
        std = standards.get(name)
        assert std is not None
        for check_id, ctrl_ids in std.mappings.items():
            for cid in ctrl_ids:
                assert cid in std.controls, (
                    f"{name}: {check_id} maps to undefined control {cid!r}"
                )

    @pytest.mark.parametrize("name", ["owasp_cicd_top_10", "cis_aws_foundations"])
    def test_standard_has_metadata(self, name):
        std = standards.get(name)
        assert std.title
        assert std.controls
        assert std.mappings


class TestCISMappings:
    def test_s3_002_maps_to_cis_2_1_1(self):
        std = standards.get("cis_aws_foundations")
        assert "2.1.1" in std.mappings["S3-002"]

    def test_iam_001_maps_to_cis_1_16(self):
        std = standards.get("cis_aws_foundations")
        assert "1.16" in std.mappings["IAM-001"]

    def test_s3_004_maps_to_cis_3_6(self):
        std = standards.get("cis_aws_foundations")
        assert "3.6" in std.mappings["S3-004"]


class TestMultiStandardEnrichment:
    def test_s3_002_gets_controls_from_both_standards(self):
        refs = standards.resolve_for_check("S3-002")
        std_names = {r.standard for r in refs}
        assert {"owasp_cicd_top_10", "cis_aws_foundations"} <= std_names

    def test_refs_are_controlref_instances(self):
        refs = standards.resolve_for_check("IAM-001")
        assert refs
        for r in refs:
            assert isinstance(r, ControlRef)
            assert r.control_id
            assert r.standard_title

    def test_unmapped_check_returns_empty(self):
        assert standards.resolve_for_check("ZZZ-999") == []

    def test_resolve_for_check_respects_standards_filter(self):
        only_cis = standards.resolve(["cis_aws_foundations"])
        refs = standards.resolve_for_check("S3-002", only_cis)
        assert refs
        assert {r.standard for r in refs} == {"cis_aws_foundations"}

    def test_pbac_001_only_in_owasp(self):
        """CIS doesn't evidence PBAC-001; only OWASP should return a ref."""
        refs = standards.resolve_for_check("PBAC-001")
        assert {r.standard for r in refs} == {"owasp_cicd_top_10"}


class TestControlRef:
    def test_label(self):
        r = ControlRef(
            standard="x", standard_title="X",
            control_id="CTRL-1", control_title="First",
        )
        assert r.label() == "CTRL-1: First"

    def test_to_dict_round_trip(self):
        r = ControlRef(
            standard="x", standard_title="X",
            control_id="CTRL-1", control_title="First",
        )
        assert r.to_dict() == {
            "standard": "x",
            "standard_title": "X",
            "control_id": "CTRL-1",
            "control_title": "First",
        }

    def test_frozen(self):
        r = ControlRef(standard="x", standard_title="X",
                       control_id="c", control_title="t")
        with pytest.raises(Exception):
            r.standard = "y"  # type: ignore[misc]
