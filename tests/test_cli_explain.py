"""Tests for the ``pipeline_check --explain CHECK_ID`` subcommand."""
from __future__ import annotations

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.rule import Rule
from pipeline_check.core.explain import (
    _build_index,
    _suggest,
    available_ids,
    render,
)

# ─── Renderer — rule-based check ───────────────────────────────────────────


def test_explain_rule_based_check_renders_all_sections():
    body, code = render("GHA-024")
    assert code == 0
    # Header with severity + confidence
    assert "GHA-024" in body
    assert "HIGH confidence" in body  # GHA-024 not in demotion list
    # Standards block
    assert "owasp_cicd_top_10" in body
    # Docs note section
    assert "[What it checks]" in body
    # Fix section
    assert "[How to fix]" in body


def test_explain_rule_based_check_shows_known_fp_when_present():
    body, code = render("GHA-016")
    assert code == 0
    assert "LOW confidence" in body  # demoted
    assert "[Known false-positive modes]" in body
    # The curl-pipe known_fp mentions vendor installers.
    assert "installer" in body.lower()


def test_explain_rule_without_known_fp_omits_section():
    body, code = render("GHA-024")
    assert code == 0
    # GHA-024 has no known_fp — the section should be absent.
    assert "[Known false-positive modes]" not in body


# ─── Renderer — AWS rule-based check (post-migration) ─────────────────────
#
# Every AWS check is now a rule module under ``aws/rules/``; the
# class-based fallback path is exercised by terraform/cloudformation
# modules whose IDs don't overlap with an AWS rule. No such IDs currently
# exist in the repo — if any reappear, add a dedicated test here.


def test_explain_cb001_renders_full_rule_sections():
    body, code = render("CB-001")
    assert code == 0
    assert "CB-001" in body
    assert "CRITICAL" in body
    # Rule-based rendering includes the docs note and fix sections.
    assert "[What it checks]" in body
    assert "[How to fix]" in body


def test_explain_iam002_shows_standards():
    body, code = render("IAM-002")
    assert code == 0
    assert "IAM-002" in body
    assert "owasp_cicd_top_10" in body


# ─── Renderer — unknown check ID ───────────────────────────────────────────


def test_explain_unknown_id_exits_3_with_suggestions():
    body, code = render("GHA-999")
    assert code == 3
    assert "Unknown check ID" in body
    assert "Did you mean" in body
    # Should suggest same-prefix IDs
    assert "GHA-" in body


def test_explain_unknown_id_case_insensitive():
    body, code = render("gha-024")
    assert code == 0
    assert "GHA-024" in body


def test_suggest_prefix_match():
    ids = ["GHA-001", "GHA-002", "CB-001", "IAM-001"]
    # prefix match wins
    assert _suggest("GHA-999", ids)[:2] == ["GHA-001", "GHA-002"]


def test_suggest_fallback_substring():
    ids = ["GHA-001", "CB-001", "IAM-001"]
    # No same-prefix match for XYZ — substring "001" returns the IDs.
    assert _suggest("001", ids) == ids


# ─── CLI integration ───────────────────────────────────────────────────────


def test_cli_explain_exit_zero_for_known_id():
    result = CliRunner().invoke(scan, ["--explain", "GHA-024"])
    assert result.exit_code == 0
    assert "GHA-024" in result.output
    assert "[How to fix]" in result.output


def test_cli_explain_exit_three_for_unknown_id():
    result = CliRunner().invoke(scan, ["--explain", "XYZ-999"])
    assert result.exit_code == 3
    assert "Unknown check ID" in result.output


def test_cli_explain_class_based_id_works():
    result = CliRunner().invoke(scan, ["--explain", "CB-001"])
    assert result.exit_code == 0
    assert "CB-001" in result.output


# ─── Rule dataclass gained known_fp ────────────────────────────────────────


def test_rule_dataclass_has_known_fp_field_defaulting_to_empty_tuple():
    from pipeline_check.core.checks.base import Severity
    r = Rule(id="X-001", title="t", severity=Severity.LOW)
    assert r.known_fp == ()


def test_rule_dataclass_known_fp_roundtrip():
    from pipeline_check.core.checks.base import Severity
    r = Rule(
        id="X-001",
        title="t",
        severity=Severity.LOW,
        known_fp=("mode A", "mode B"),
    )
    assert r.known_fp == ("mode A", "mode B")


# ─── Index coverage ────────────────────────────────────────────────────────


def test_available_ids_includes_rule_based_and_class_based():
    ids = set(available_ids())
    # Rule-based
    assert "GHA-024" in ids
    # Class-based (AWS core)
    assert "CB-001" in ids
    assert "IAM-001" in ids


def test_build_index_is_cached_across_calls():
    first = _build_index()
    second = _build_index()
    assert first is second  # Same object — memoized.


# ─── Manual integration ────────────────────────────────────────────────────


def test_man_topic_explain_listed():
    from pipeline_check.core import manual

    assert "explain" in manual.topics()
    body = manual.render("explain")
    assert "TOPIC: explain" in body
    assert "--explain" in body


# ─── Every rule pack is registered in _RULE_PACKAGES ──────────────────────
#
# Pre-2026-05 history: only seven rule packs were registered, leaving
# kubernetes / dockerfile / cloudbuild / buildkite / tekton / argo /
# helm with no ``--explain`` coverage even though the rule modules
# fully populated their ``Rule`` metadata. The walker below discovers
# every ``rules/`` package on disk, then asserts each rule's ID
# resolves through the explain renderer. A new rule pack added without
# updating ``_RULE_PACKAGES`` trips this test.


def _discover_all_rule_packages() -> list[str]:
    """Find every ``pipeline_check.core.checks.<provider>.rules`` package.

    Walks the filesystem rather than the providers registry — a rule
    pack is anything with a populated ``rules/`` dir, regardless of
    whether the provider has been wired into ``providers/__init__.py``.
    """
    from pathlib import Path

    import pipeline_check.core.checks as checks_pkg

    checks_root = Path(checks_pkg.__file__).parent
    out: list[str] = []
    for child in sorted(checks_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("_"):
            continue
        rules_dir = child / "rules"
        if not rules_dir.is_dir():
            continue
        # Confirm the dir actually has rule modules (not just an empty
        # __init__.py — empty packs contribute no IDs to test).
        has_rules = any(
            f.suffix == ".py"
            and f.name not in {"__init__.py"}
            and not f.name.startswith("_")
            for f in rules_dir.iterdir()
        )
        if has_rules:
            out.append(f"pipeline_check.core.checks.{child.name}.rules")
    return out


def test_every_rule_pack_is_registered_in_explain_index():
    """Every ``rules/`` dir on disk must be in ``_RULE_PACKAGES``.

    This is the structural lock — the dynamic test below verifies the
    same coverage by walking IDs, but this one fails with a clearer
    error message when a contributor forgets ``_RULE_PACKAGES``.
    """
    from pipeline_check.core.explain import _RULE_PACKAGES

    discovered = set(_discover_all_rule_packages())
    registered = set(_RULE_PACKAGES)
    missing = discovered - registered
    assert not missing, (
        f"Rule packs on disk but missing from "
        f"pipeline_check.core.explain._RULE_PACKAGES: "
        f"{sorted(missing)}. ``--explain`` will fail to resolve their "
        f"IDs until they're added."
    )


def test_every_discovered_rule_id_renders():
    """For every rule across every registered pack, ``render(id)``
    returns exit code 0 and a populated body.

    Catches both the structural-registration failure and a deeper
    case where a rule module imports cleanly but its metadata can't
    be rendered (e.g. a Severity enum drift).
    """
    from pipeline_check.core.checks.rule import discover_rules
    from pipeline_check.core.explain import _RULE_PACKAGES

    failures: list[str] = []
    for pkg_fqn in _RULE_PACKAGES:
        for rule, _ in discover_rules(pkg_fqn):
            body, code = render(rule.id)
            if code != 0:
                failures.append(
                    f"{rule.id} from {pkg_fqn}: render exited {code}"
                )
                continue
            if rule.id not in body:
                failures.append(
                    f"{rule.id}: rendered body did not contain the ID"
                )
            if rule.title not in body:
                failures.append(
                    f"{rule.id}: rendered body did not contain the title"
                )
    assert not failures, "\n".join(failures)


# ─── Triggers-attack-chains cross-reference ───────────────────────────


def test_every_chain_declares_triggering_check_ids():
    """Every chain rule must populate ``triggering_check_ids``.

    The rule-side ``--explain`` output uses this field to surface
    chains that include the rule. A chain that ships with an empty
    field becomes invisible to that lookup, breaking the cross-
    reference for any rule whose check_id the chain consumes.
    """
    from pipeline_check.core.chains import list_rules

    missing = [r.id for r in list_rules() if not r.triggering_check_ids]
    assert not missing, (
        f"Chain rule(s) without triggering_check_ids: {missing}. "
        f"Populate the field on the ChainRule so --explain RULE_ID "
        f"can surface the rule -> chain link."
    )


def test_explain_surfaces_triggering_attack_chains_section():
    """``--explain GHA-001`` should list AC-* chains it triggers."""
    body, code = render("GHA-001")
    assert code == 0
    assert "[Triggers attack chains]" in body
    # GHA-001 is in AC-003, AC-009, AC-018 — confirm at least the
    # AC-009 link is rendered.
    assert "AC-009" in body
    assert "AC-018" in body


def test_explain_omits_chain_section_for_check_id_with_no_chains():
    """A rule no chain references shouldn't render the section."""
    # GHA-022 is a Dependabot/Renovate check — no chain has it in
    # its triggering set as of this round.
    body, code = render("GHA-022")
    assert code == 0
    assert "[Triggers attack chains]" not in body


def test_chains_for_check_id_helper_caches():
    """The lookup is cached; first call builds the index, subsequent
    calls reuse it. Confirms the cache hook is wired."""
    from pipeline_check.core import explain as explain_mod

    explain_mod._CHAINS_BY_CHECK_ID = None  # type: ignore[assignment]
    chains_first = explain_mod._chains_for_check_id("GHA-001")
    assert explain_mod._CHAINS_BY_CHECK_ID is not None
    chains_second = explain_mod._chains_for_check_id("GHA-001")
    # Same list object on the second call — proves the cache hit.
    assert chains_first == chains_second
