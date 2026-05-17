"""Tests for the compliance standards registry and built-in standards."""
from __future__ import annotations

import ast
import pathlib

import pytest

from pipeline_check.core import standards
from pipeline_check.core.standards import data as _standards_data
from pipeline_check.core.standards.base import ControlRef, Standard

_DATA_DIR = pathlib.Path(_standards_data.__file__).parent
_DATA_MODULES = sorted(
    p for p in _DATA_DIR.glob("*.py") if p.name != "__init__.py"
)


class TestRegistry:
    def test_all_builtin_standards_registered(self):
        names = standards.available()
        for expected in (
            "owasp_cicd_top_10",
            "cis_aws_foundations",
            "cis_supply_chain",
            "nist_ssdf",
            "nist_800_53",
            "slsa",
            "pci_dss_v4",
            "openssf_scorecard",
            "s2c2f",
            "soc2",
            "nist_csf_2",
            "nist_800_190",
        ):
            assert expected in names

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

    @pytest.mark.parametrize("name", [
        "owasp_cicd_top_10",
        "cis_aws_foundations",
        "cis_supply_chain",
        "nist_ssdf",
        "nist_800_53",
        "slsa",
        "pci_dss_v4",
        "openssf_scorecard",
        "s2c2f",
        "soc2",
        "nist_csf_2",
        "nist_800_190",
    ])
    def test_every_mapped_control_is_defined(self, name):
        std = standards.get(name)
        assert std is not None
        for check_id, ctrl_ids in std.mappings.items():
            for cid in ctrl_ids:
                assert cid in std.controls, (
                    f"{name}: {check_id} maps to undefined control {cid!r}"
                )

    @pytest.mark.parametrize("name", [
        "owasp_cicd_top_10",
        "cis_aws_foundations",
        "cis_supply_chain",
        "nist_ssdf",
        "nist_800_53",
        "slsa",
        "pci_dss_v4",
        "openssf_scorecard",
        "s2c2f",
        "soc2",
        "nist_csf_2",
        "nist_800_190",
    ])
    def test_standard_has_metadata(self, name):
        std = standards.get(name)
        assert std.title
        assert std.controls
        assert std.mappings


class TestCheckIdIntegrity:
    """Every check_id used by any standard must appear in the canonical OWASP
    mapping — OWASP covers the full scanner check set, so other standards
    mapping an unknown ID is a typo."""

    @pytest.mark.parametrize("name", [
        "cis_aws_foundations",
        "cis_supply_chain",
        "nist_ssdf",
        "nist_800_53",
        "slsa",
        "pci_dss_v4",
        "openssf_scorecard",
        "s2c2f",
        "soc2",
        "nist_csf_2",
        "nist_800_190",
    ])
    def test_check_ids_are_known(self, name):
        owasp = standards.get("owasp_cicd_top_10")
        std = standards.get(name)
        for check_id in std.mappings:
            assert check_id in owasp.mappings, (
                f"{name} maps unknown check_id {check_id!r} "
                "(not present in canonical OWASP mapping)"
            )


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

    def test_pbac_001_not_in_cis(self):
        """CIS is AWS-host-focused and doesn't evidence PBAC-001."""
        refs = standards.resolve_for_check("PBAC-001")
        std_names = {r.standard for r in refs}
        assert "cis_aws_foundations" not in std_names
        assert "owasp_cicd_top_10" in std_names


class TestDataFileHygiene:
    """Source-level guards that the runtime API can't catch.

    Python dict literals allow duplicate keys silently (last-write-wins).
    When a check_id evidences multiple controls in the same standard,
    a drafter may write ``"CB-005": ["A"]`` and later ``"CB-005": ["B"]``
    in the same dict — the first mapping is silently lost. Runtime
    integrity tests walk the *collapsed* dict and can't see it. This
    suite parses the source AST to catch duplicates before they ship.
    """

    @pytest.mark.parametrize("path", _DATA_MODULES, ids=lambda p: p.stem)
    def test_no_duplicate_dict_keys(self, path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys: list[object] = []
            for k in node.keys:
                if isinstance(k, ast.Constant):
                    keys.append(k.value)
            dupes = sorted({k for k in keys if keys.count(k) > 1})
            assert not dupes, (
                f"{path.name}: duplicate dict keys {dupes} "
                f"(Python silently keeps only the last — consolidate "
                f"into a single list value)"
            )


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
        import dataclasses
        r = ControlRef(standard="x", standard_title="X",
                       control_id="c", control_title="t")
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.standard = "y"  # type: ignore[misc]


# ── Cross-pack OWASP coverage ────────────────────────────────────────
#
# Every rule in a ``rules/`` package declares its OWASP control(s)
# in the ``Rule.owasp`` tuple. The authoritative mapping lives in
# ``owasp_cicd_top_10.py`` and is what reporters / SARIF / explain
# read at runtime. Pre-2026-05 there was a 36-rule gap between the
# two: rules declared an OWASP tag in their metadata but the data
# file hadn't been backfilled, so ``resolve_for_check`` returned
# nothing.
#
# These tests lock the gap closed: every rule must (a) be present
# in the OWASP mapping, and (b) carry every control its
# ``Rule.owasp`` declared. A new rule that lands without a backfill
# trips both.


def _all_rule_packs() -> list[str]:
    """Walk the filesystem to enumerate every ``rules/`` package."""
    from pathlib import Path

    import pipeline_check.core.checks as checks_pkg

    checks_root = Path(checks_pkg.__file__).parent
    out: list[str] = []
    for child in sorted(checks_root.iterdir()):
        if not child.is_dir() or child.name.startswith("_"):
            continue
        rules_dir = child / "rules"
        if not rules_dir.is_dir():
            continue
        if any(
            f.suffix == ".py" and f.name not in {"__init__.py"}
            and not f.name.startswith("_")
            for f in rules_dir.iterdir()
        ):
            out.append(f"pipeline_check.core.checks.{child.name}.rules")
    return out


class TestEveryRuleHasDocsNote:
    """Every rule must populate ``Rule.docs_note`` so ``--explain``
    has a body to render in the [What it checks] section.

    Pre-2026-05 history: the AWS rule pack shipped 58 rules with an
    empty ``docs_note`` field — a migration artifact from the
    class-based-to-rule-based refactor. ``pipeline_check --explain
    IAM-001`` rendered the header + recommendation but no
    threat-model body, leaving operators without the "why this
    check matters" framing other packs always had."""

    def test_every_rule_has_non_empty_docs_note(self):
        from pipeline_check.core.checks.rule import discover_rules

        missing: list[str] = []
        for pack in _all_rule_packs():
            for rule, _ in discover_rules(pack):
                if not rule.docs_note or not rule.docs_note.strip():
                    missing.append(f"{rule.id} ({pack})")
        assert not missing, (
            f"{len(missing)} rules without ``docs_note``: "
            f"{missing[:10]}{'…' if len(missing) > 10 else ''}. "
            f"Add a 1-3 sentence docs_note explaining the threat "
            f"model — distinct from the recommendation's how-to-fix."
        )


class TestEveryRuleHasOwaspMapping:

    def test_every_discovered_rule_appears_in_owasp_data_file(self):
        from pipeline_check.core.checks.rule import discover_rules
        owasp = standards.get("owasp_cicd_top_10").mappings
        missing: list[str] = []
        for pack in _all_rule_packs():
            for rule, _ in discover_rules(pack):
                if rule.id not in owasp:
                    missing.append(f"{rule.id} ({pack})")
        assert not missing, (
            f"{len(missing)} rules with no OWASP mapping in "
            f"owasp_cicd_top_10.py: {missing[:8]}"
            f"{'…' if len(missing) > 8 else ''}. Add the entries to "
            f"the data file's ``mappings`` dict."
        )

    def test_owasp_data_matches_each_rules_declared_tags(self):
        """``Rule.owasp`` must agree with the data file.

        The rule module's ``owasp=("CICD-SEC-X",)`` tuple is the
        author's declaration of which OWASP controls evidence the
        finding. The data-file mapping is what the runtime reads.
        Drift between the two means the reporter / SARIF / explain
        render the wrong control set even though the rule "knows"
        the right one.
        """
        from pipeline_check.core.checks.rule import discover_rules
        owasp = standards.get("owasp_cicd_top_10").mappings
        drift: list[str] = []
        for pack in _all_rule_packs():
            for rule, _ in discover_rules(pack):
                if not rule.owasp:
                    continue
                declared = set(rule.owasp)
                mapped = set(owasp.get(rule.id, []))
                missing = declared - mapped
                if missing:
                    drift.append(
                        f"{rule.id}: Rule.owasp declares {sorted(declared)} "
                        f"but data file has {sorted(mapped)} (missing: {sorted(missing)})"
                    )
        assert not drift, (
            f"{len(drift)} rules whose declared OWASP tags don't all "
            f"appear in the data file:\n  " + "\n  ".join(drift[:10])
            + ("\n  …" if len(drift) > 10 else "")
        )


class TestPerFrameworkCoverageFloor:
    """Lock the per-framework coverage % above documented floors.

    Each backfill round ratchets these upward; a future contributor
    that adds a rule pack and forgets to map it across the
    supply-chain frameworks (SLSA / OpenSSF / CIS / ESF / NIST) will
    drop the percentage on at least one and trip the assertion. The
    floors are a couple percent below current state to absorb a
    single-rule addition without a CI break.
    """

    # (standard_name, minimum coverage percent of the rule-pack catalog).
    # Set just below current state so a single rule lands without
    # tripping; a coordinated pack add or framework regression does
    # trip. Bump the floor in the same PR that lifts the actual
    # number — that's the ratchet.
    FLOORS: dict[str, int] = {
        "owasp_cicd_top_10":   100,
        # nist_csf_2 lowered from 70 to 69 when GHA-040 + the SCM
        # rule pack landed without nist_csf_2 mappings. Backfill is
        # queued for a follow-up; nist_csf_2 mappings cluster around
        # asset / risk-management controls that don't apply to most
        # of the new rules. Lowered from 69 to 68 when ATTEST-005
        # (subject-digest unpinned) landed; the ATTEST-NNN family
        # has no nist_csf_2 mappings today, same denominator-
        # dilution case as the SCM pack. Lowered from 68 to 67 when
        # the npm + pypi dependency-supply-chain packs (NPM-001..005
        # / PYPI-001..005) landed OWASP-only; backfill is queued.
        # Lowered from 67 to 66 when NPM-006 / PYPI-006 (curated
        # compromised-package registries) landed OWASP-only.
        # Lowered from 66 to 65 when SCM-020..025 (Actions governance
        # + environments + deploy-keys) landed OWASP-only.
        "nist_csf_2":           65,
        # Lowered from 58 to 57 when SCM-030 (ruleset always-bypass)
        # landed OWASP-only; ESF backfill queued.
        "esf_supply_chain":     57,
        # openssf_scorecard lowered from 57 to 56 when NPM-011
        # (secrets-in-files-field) landed OWASP-only; Scorecard
        # backfill queued. (SCM-020..025 are already a no-op here.)
        # Lowered from 56 to 55 when SCM-026/027/028 landed
        # OWASP-only (Scorecard backfill queued).
        "openssf_scorecard":    55,
        # nist_800_53 lowered from 55 to 54 when the SCM provider
        # added 10 rules (none NIST 800-53 mapped today; SCM is
        # already in OWASP, CIS SSCS, and Scorecard, and 800-53
        # mapping is queued for a follow-up). Rounded the
        # percentage below the original threshold without any
        # regression on the underlying mappings. Lowered again from
        # 54 to 53 when SCM-017/018/019 (CODEOWNERS / bypass /
        # push restrictions) added three more denominator entries
        # without 800-53 mappings, same denominator-dilution case.
        # nist_800_53 absorbs two unmapped landings on this merge:
        # ATTEST-004 (materials gap) from master and GHA-047 (fresh-
        # ref cooldown) from this branch. Neither family has an
        # 800-53 mapping today; SR-family + ATTEST-NNN backfills are
        # queued separately. Same denominator-dilution case.
        # Lowered from 51 to 50 when the SCM-020..025 pack landed
        # OWASP-only; backfill queued.
        "nist_800_53":          50,
        # Lowered from 45 to 44 when ATTEST-006 + ATTEST-007 landed.
        # The ATTEST-NNN family has no nist_800_190 mappings today
        # (800-190 is container-isolation focused, the attestation-
        # content rules are provenance-focused). Same denominator-
        # dilution case as earlier ATTEST landings. Lowered from 44
        # to 43 when the worm-mitigation pack (GHA-048/049/050 +
        # DF-024/025) landed without nist_800_190 mappings; backfill
        # is queued. Lowered from 43 to 42 when the npm + pypi
        # dependency-supply-chain packs landed OWASP-only.
        # Lowered from 42 to 41 when SCM-020..025 landed OWASP-only.
        "nist_800_190":         41,
        # slsa lowered from 42 to 41 for the same SCM-017/018/019
        # denominator-dilution case: SLSA is provenance-focused and
        # the three new SCM rules cover review-control surface, not
        # provenance. No regression on the existing SLSA mappings.
        # Lowered from 41 to 40 when NPM-001..005 / PYPI-001..005
        # landed OWASP-only; SLSA backfill is queued for the
        # dependency-supply-chain pack.
        # Lowered from 40 to 39 when SCM-020..025 landed OWASP-only.
        "slsa":                 39,
        # Lowered from 48 to 47 when SCM-020..025 landed OWASP-only.
        "soc2":                 47,
        "cis_supply_chain":     28,
        # s2c2f absorbs two unmapped landings on this merge: ATTEST-
        # 004 from master and GHA-047 from this branch. Neither
        # family has an S2C2F mapping today (GHA-04x reputation pack
        # is uncovered; ATTEST-NNN backfill is queued). Denominator-
        # dilution case. Lowered from 28 to 27 when the worm-
        # mitigation pack (GHA-048/049/050 + DF-024/025) landed
        # without S2C2F mappings; backfill is queued.
        # Lowered from 27 to 26 when SCM-020..025 landed OWASP-only.
        "s2c2f":                26,
        "nist_ssdf":            18,
        "pci_dss_v4":           27,
        # cis_aws_foundations is intentionally narrow: only AWS-pack
        # rules can map to it, and not all of them have a CIS
        # Foundations analog. The floor caps catalog-wide coverage
        # at the AWS-pack share, not the full 363 rules.
        # Lowered from 9 to 8 when the SCM provider added 10 rules
        # (none AWS-relevant); same denominator-dilution case as
        # cis_kubernetes below. Lowered from 8 to 7 when SCM-020..
        # 025 (Actions / environments / deploy-keys) landed, same
        # case — none AWS-relevant.
        "cis_aws_foundations":   7,
        # cis_kubernetes is also intentionally narrow: only the K8s
        # pack (and a few Helm-rendered K8s rules) map to it. The
        # floor caps coverage at the K8s-pack share — most of the
        # catalog is non-K8s and never enters the denominator.
        # Lowered from 7 to 6 when the SCM provider added 8 rules
        # (none K8s-relevant) and rounded the percentage below the
        # original threshold without any K8s-coverage regression.
        "cis_kubernetes":        6,
    }

    def test_floors_hold(self):
        from pipeline_check.core.checks.rule import discover_rules

        rule_ids: list[str] = []
        for pack in _all_rule_packs():
            for rule, _ in discover_rules(pack):
                rule_ids.append(rule.id)
        total = len(rule_ids)

        per_std: dict[str, int] = {name: 0 for name in self.FLOORS}
        for rid in rule_ids:
            stds = {x.standard for x in standards.resolve_for_check(rid)}
            for s in stds:
                if s in per_std:
                    per_std[s] += 1

        below: list[str] = []
        for std, floor in self.FLOORS.items():
            pct = 100 * per_std[std] // max(1, total)
            if pct < floor:
                below.append(
                    f"{std}: {per_std[std]}/{total} = {pct}% "
                    f"(floor {floor}%)"
                )
        assert not below, (
            "Standards coverage dropped below floor:\n  "
            + "\n  ".join(below)
            + "\n\nEither backfill the affected mappings or, if the "
            "drop is intentional (e.g. a new rule pack landed and "
            "the matching framework mappings are deferred to a "
            "follow-up), lower the floor in this test deliberately."
        )
