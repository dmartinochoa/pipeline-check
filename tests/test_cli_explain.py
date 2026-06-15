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
    body, code = render("GHA-002")
    assert code == 0
    # Header with severity + confidence
    assert "GHA-002" in body
    # GHA-002 is a structural active-risk rule, not in any demotion list.
    assert "HIGH confidence" in body
    # Standards block
    assert "owasp_cicd_top_10" in body
    # Docs note section
    assert "[What it checks]" in body
    # Fix section
    assert "[How to fix]" in body


def test_explain_orders_compliance_after_plain_english():
    # The body must lead with the what/how an operator opened explain
    # for; the control crosswalk + CWE are reference material at the foot.
    body, code = render("GHA-001")
    assert code == 0
    assert "[Compliance & standards]" in body
    assert body.index("[What it checks]") < body.index("[Compliance & standards]")
    assert body.index("[How to fix]") < body.index("[Compliance & standards]")
    assert body.index("[How to fix]") < body.index("owasp_cicd_top_10")
    # CWE now rides inside the compliance block, not at the top.
    assert body.index("[Compliance & standards]") < body.index("CWE: CWE-829")


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


def test_explain_renders_incident_refs_when_present():
    """Marquee rules carry ``incident_refs`` citations that
    ``--explain`` surfaces under a "Seen in the wild" section."""
    body, code = render("GHA-001")
    assert code == 0
    assert "[Seen in the wild]" in body
    # GHA-001 cites tj-actions/changed-files (CVE-2025-30066).
    assert "tj-actions" in body
    assert "CVE-2025-30066" in body


def test_explain_omits_seen_in_the_wild_section_when_no_refs():
    """A rule without ``incident_refs`` populated should not render
    the section header at all (no empty list, no placeholder)."""
    # GHA-024 has no incident_refs populated.
    body, code = render("GHA-024")
    assert code == 0
    assert "[Seen in the wild]" not in body


def test_explain_renders_proof_of_exploit_when_present():
    """Marquee HIGH/CRITICAL rules carry an ``exploit_example`` that
    --explain surfaces under a "Proof of exploit" section so reviewers
    see the concrete attack rather than inferring from prose."""
    body, code = render("GHA-001")
    assert code == 0
    assert "[Proof of exploit]" in body
    # GHA-001's example shows the tag-pinned vulnerable form and the
    # SHA-pinned safe form back-to-back.
    assert "tj-actions/changed-files@v45" in body
    assert "tj-actions/changed-files@a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93" in body


def test_explain_proof_of_exploit_preserves_multi_line_layout():
    """The exploit_example field carries multi-line code blocks; the
    renderer should preserve their line structure verbatim (each line
    indented to match the section body)."""
    body, code = render("K8S-013")
    assert code == 0
    assert "[Proof of exploit]" in body
    # The K8S-013 sample includes a manifest fragment with hostPath at /
    assert "hostPath:" in body
    assert "path: /" in body


def test_explain_omits_proof_of_exploit_when_unset():
    """A rule without ``exploit_example`` populated should not render
    the section header at all."""
    body, code = render("GHA-024")
    assert code == 0
    assert "[Proof of exploit]" not in body


def test_explain_renders_proof_of_exploit_for_pwn_request():
    """GHA-002 (pull_request_target + checkout PR head) is the
    canonical pwn-request primitive driving XPC-006. The exploit
    snippet must show both the vulnerable single-workflow form and
    the safe split-workflow remediation."""
    body, code = render("GHA-002")
    assert code == 0
    assert "[Proof of exploit]" in body
    # Vulnerable form: single workflow with both pull_request_target
    # and the PR-head checkout.
    assert "pull_request_target" in body
    assert "github.event.pull_request.head.sha" in body
    # Safe remediation: split into labeler + builder.
    assert "split" in body.lower() or "labeler" in body.lower() or \
        "triage" in body.lower()


def test_explain_renders_proof_of_exploit_for_script_injection():
    """GHA-003 (script injection via untrusted context) is one half
    of the GitHub Security Lab pwn-request research. The snippet
    must show the title-injection payload pattern."""
    body, code = render("GHA-003")
    assert code == 0
    assert "[Proof of exploit]" in body
    # Vulnerable interpolation pattern.
    assert "github.event.pull_request.title" in body
    # Safe env-routing pattern.
    assert "PR_TITLE" in body or "env:" in body


def test_explain_renders_proof_of_exploit_for_token_persistence():
    """GHA-019 (token persistence) drives XPC-004. The snippet
    must show the artifact-exfil loop the chain is built around."""
    body, code = render("GHA-019")
    assert code == 0
    assert "[Proof of exploit]" in body
    # Vulnerable persistence pattern.
    assert "GITHUB_TOKEN" in body
    # Reference to the artifact-download exfil mechanism.
    assert "upload-artifact" in body or "download" in body.lower()


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

    AWS / Terraform / CloudFormation deliberately share rule IDs
    (one logical control, three detection surfaces) and their titles
    diverge in minor ways (``filter group`` vs ``filter_group``). The
    explain index only renders one title per ID, so for shared IDs
    the body just needs to match *some* registered title.
    """
    from pipeline_check.core.checks.rule import discover_rules
    from pipeline_check.core.explain import _RULE_PACKAGES

    titles_by_id: dict[str, set[str]] = {}
    sources_by_id: dict[str, list[str]] = {}
    for pkg_fqn in _RULE_PACKAGES:
        for rule, _ in discover_rules(pkg_fqn):
            titles_by_id.setdefault(rule.id, set()).add(rule.title)
            sources_by_id.setdefault(rule.id, []).append(pkg_fqn)

    failures: list[str] = []
    for rule_id, titles in titles_by_id.items():
        body, code = render(rule_id)
        if code != 0:
            failures.append(
                f"{rule_id} from {sources_by_id[rule_id]}: render exited {code}"
            )
            continue
        if rule_id not in body:
            failures.append(f"{rule_id}: rendered body did not contain the ID")
        if not any(title in body for title in titles):
            failures.append(
                f"{rule_id}: rendered body did not contain any registered "
                f"title (expected one of {sorted(titles)})"
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


# ─── Topic-clustered related rules ────────────────────────────────────


def test_topic_clusters_reference_real_check_ids():
    """Every check_id in every cluster must resolve through the index.

    Catches typos and IDs that were removed without updating the
    cluster table.
    """
    from pipeline_check.core.explain import _TOPIC_CLUSTERS, _build_index

    index = _build_index()
    missing: list[tuple[str, str]] = []
    for cluster, members in _TOPIC_CLUSTERS.items():
        for cid in members:
            if cid not in index:
                missing.append((cluster, cid))
    assert not missing, (
        f"Topic-cluster entries referencing unknown check IDs: {missing}. "
        f"Either fix the typo, remove the ID, or add the missing rule."
    )


def test_related_check_ids_unions_across_clusters():
    """A check in two clusters returns the union of both, deduped, "
    "without itself."""
    from pipeline_check.core.explain import _related_check_ids

    # K8S-012 is in both ``k8s_service_account`` and an ARGO/TKN
    # cluster context; its related set must include companions from
    # both clusters and exclude K8S-012 itself.
    related = _related_check_ids("K8S-012")
    assert "K8S-012" not in related
    assert "K8S-034" in related  # k8s_service_account
    assert "K8S-011" in related  # k8s_service_account


def test_related_check_ids_empty_for_uncategorized_rule():
    """A rule no cluster references returns an empty tuple."""
    from pipeline_check.core.explain import _related_check_ids

    # GHA-022 (Dependabot/Renovate config) isn't in any current
    # topic cluster — confirms the empty-tuple return shape.
    assert _related_check_ids("GHA-022") == ()


def test_related_check_ids_caches_inverted_index():
    """First call builds the inverted index; subsequent calls reuse it."""
    from pipeline_check.core import explain as explain_mod

    explain_mod._RELATED_BY_CHECK_ID = None  # type: ignore[assignment]
    explain_mod._related_check_ids("K8S-005")
    assert explain_mod._RELATED_BY_CHECK_ID is not None
    explain_mod._related_check_ids("K8S-005")
    # No assertion on object identity — the function returns a tuple
    # of strings, not the cached set.


def test_explain_renders_related_rules_section():
    """``--explain K8S-005`` lists its securityContext siblings."""
    body, code = render("K8S-005")
    assert code == 0
    assert "[Related rules]" in body
    # K8S-005 is in the k8s_security_context cluster with K8S-006/007/035.
    assert "K8S-006" in body
    assert "K8S-007" in body


def test_explain_omits_related_rules_section_when_no_cluster():
    """A rule no cluster contains shouldn't render the section."""
    body, code = render("GHA-022")
    assert code == 0
    assert "[Related rules]" not in body


# ─── Autofixable cross-reference ──────────────────────────────────────


def test_explain_renders_autofixable_section_for_registered_fixer():
    """A check with a registered fixer surfaces an `[Autofixable]` line."""
    from pipeline_check.core.autofix import available_fixers

    fixers = set(available_fixers())
    assert fixers, "expected at least one registered fixer"
    sample = next(iter(sorted(fixers)))
    body, code = render(sample)
    assert code == 0, body
    assert "[Autofixable]" in body
    assert "--fix" in body


def test_explain_omits_autofixable_section_when_no_fixer():
    """A check without a registered fixer doesn't render the section."""
    from pipeline_check.core.autofix import available_fixers
    from pipeline_check.core.explain import available_ids

    all_ids = set(available_ids())
    fixers = set(available_fixers())
    no_fix = sorted(all_ids - fixers)
    assert no_fix, "expected at least one check with no fixer"
    body, code = render(no_fix[0])
    assert code == 0
    assert "[Autofixable]" not in body
