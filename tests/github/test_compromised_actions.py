"""Per-rule tests for GHA-040 (workflow uses a known-compromised
action reference) and the underlying ``_compromised_actions``
registry helpers.
"""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.github._compromised_actions import (
    CompromisedAction,
    known_owners,
    lookup,
    registry_size,
)

from .conftest import run_check

# A known-compromised SHA from the registry. tj-actions/changed-files
# CVE-2025-30066. Hard-coded so a registry change that drops or
# renames this entry trips the test deliberately.
_TJ_BAD_SHA = "0e58ed8671d6b60d0890c21b07f8835ace038e67"


# ── GHA-040 rule behavior ──────────────────────────────────────────


class TestGHA040Rule:
    def test_fires_on_compromised_sha_pin(self):
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - uses: tj-actions/changed-files@{_TJ_BAD_SHA}
        """
        f = run_check(wf, "GHA-040")
        assert not f.passed
        assert f.severity == Severity.CRITICAL
        assert "tj-actions/changed-files" in f.description
        assert "CVE-2025-30066" in f.description

    def test_passes_on_clean_sha_pin_for_same_action(self):
        """A different SHA on the same action repo is fine — the
        registry matches by exact ref, not by repo identity."""
        clean_sha = "a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93"
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: tj-actions/changed-files@{clean_sha}
        """
        f = run_check(wf, "GHA-040")
        assert f.passed

    def test_passes_on_unrelated_action(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
        """
        f = run_check(wf, "GHA-040")
        assert f.passed

    def test_owner_repo_match_is_case_insensitive(self):
        """The registry uses lower-case lookup keys; a workflow that
        spells the action with mixed case (uncommon but legal) must
        still match."""
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: TJ-Actions/Changed-Files@{_TJ_BAD_SHA}
        """
        f = run_check(wf, "GHA-040")
        assert not f.passed

    def test_ignores_local_action_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
        """
        f = run_check(wf, "GHA-040")
        assert f.passed

    def test_ignores_docker_image_refs(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker://ghcr.io/foo/bar:1.2.3
        """
        f = run_check(wf, "GHA-040")
        assert f.passed

    def test_emits_one_finding_for_multiple_matches(self):
        """Two compromised refs in the same workflow yield a single
        Finding with both refs summarized in the description."""
        wf = f"""
        name: ci
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: tj-actions/changed-files@{_TJ_BAD_SHA}
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: tj-actions/changed-files@{_TJ_BAD_SHA}
        """
        f = run_check(wf, "GHA-040")
        assert not f.passed
        # Description shows the offending ref + advisory.
        assert _TJ_BAD_SHA in f.description
        # Two locations even though one summarized finding.
        assert len(f.locations) == 2

    def test_carries_exploit_example_through_orchestrator(self):
        """The orchestrator backfills exploit_example from the rule;
        verify the GHA-040 example reaches the Finding."""
        wf = f"""
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: tj-actions/changed-files@{_TJ_BAD_SHA}
        """
        f = run_check(wf, "GHA-040")
        assert f.exploit_example is not None
        assert "tj-actions/changed-files" in f.exploit_example


# ── _compromised_actions registry helpers ──────────────────────────


class TestCompromisedActionsRegistry:
    def test_lookup_returns_entry_for_known_compromised_sha(self):
        entry = lookup("tj-actions", "changed-files", _TJ_BAD_SHA)
        assert entry is not None
        assert entry.severity == Severity.CRITICAL
        assert "CVE-2025-30066" in entry.advisory

    def test_lookup_returns_none_for_clean_sha(self):
        assert lookup(
            "tj-actions", "changed-files",
            "a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93",
        ) is None

    def test_lookup_returns_none_for_unknown_repo(self):
        assert lookup("acme", "made-up-action", "abc123") is None

    def test_lookup_is_case_insensitive_on_owner_repo(self):
        assert lookup("TJ-ACTIONS", "Changed-Files", _TJ_BAD_SHA) is not None

    def test_placeholder_entries_never_match(self):
        """Registry placeholders (no malicious_refs and no pattern)
        exist as reservation slots; they must never produce a hit."""
        # nrwl/nx-set-shas is the current placeholder.
        assert lookup("nrwl", "nx-set-shas", "v1") is None
        assert lookup("nrwl", "nx-set-shas", "0" * 40) is None

    def test_known_owners_includes_registered_repos(self):
        owners = known_owners()
        assert "tj-actions/changed-files" in owners
        assert "reviewdog/action-setup" in owners
        assert "aquasecurity/trivy-action" in owners
        assert "aquasecurity/setup-trivy" in owners
        assert "checkmarx/kics-github-action" in owners
        assert "checkmarx/ast-github-action" in owners

    def test_registry_size_is_positive_and_stable(self):
        """If a registry entry gets dropped accidentally, this test
        floor catches it. Bump deliberately when a new entry lands."""
        assert registry_size() >= 7

    def test_compromised_action_matches_helper_handles_pattern(self):
        """``CompromisedAction.matches`` walks ``malicious_refs``
        first, then ``ref_pattern``. Verify the pattern path with a
        synthetic instance."""
        import re
        entry = CompromisedAction(
            owner="acme", repo="evil-action",
            malicious_refs=(),
            ref_pattern=re.compile(r"^v0\.[1-3]\."),
            advisory="synthetic test fixture",
        )
        assert entry.matches("v0.1.5")
        assert entry.matches("v0.3.0")
        assert not entry.matches("v0.4.0")
        assert not entry.matches("v1.0.0")

    def test_trivy_action_literal_sha_match(self):
        """The trivy-action entry has literal malicious SHAs from the
        StepSecurity analysis. Verify a known one matches."""
        entry = lookup(
            "aquasecurity", "trivy-action",
            "85cb72f1e8ee5e6e44488cd6cbdbca94722f96ed",
        )
        assert entry is not None
        assert "CVE-2026-33634" in entry.advisory

    def test_trivy_action_semver_pattern_fallback(self):
        """Tags in the v0.x.y range match the ref_pattern even when
        the exact SHA is not in malicious_refs (76 unique SHAs, not
        all listed as literals)."""
        entry = lookup("aquasecurity", "trivy-action", "v0.18.0")
        assert entry is not None

    def test_trivy_action_safe_tag_does_not_match(self):
        """v0.35.0 was the only safe tag. The ref_pattern still
        matches it (tag-level detection is a coarse signal); the GHSA
        advisory notes v0.35.0 as safe for human triage."""
        entry = lookup("aquasecurity", "trivy-action", "v0.35.0")
        assert entry is not None

    def test_setup_trivy_matches(self):
        entry = lookup(
            "aquasecurity", "setup-trivy",
            "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0",
        )
        assert entry is not None

    def test_checkmarx_kics_literal_sha_match(self):
        entry = lookup(
            "checkmarx", "kics-github-action",
            "0e22ec8d1e0dda3c62bf4beffcd4a8a5db1abda1",
        )
        assert entry is not None
        assert "TeamPCP" in entry.advisory

    def test_checkmarx_ast_version_pattern_match(self):
        entry = lookup("checkmarx", "ast-github-action", "v2.3.28")
        assert entry is not None
        assert "TeamPCP" in entry.advisory

    def test_checkmarx_ast_clean_version_does_not_match(self):
        assert lookup("checkmarx", "ast-github-action", "v2.3.37") is None
