"""Tests for the HTML reporter."""
from __future__ import annotations

import re

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.html_reporter import (
    _PROVIDER_PREFIXES,
    _provider_for,
    report_html,
)
from pipeline_check.core.standards.base import ControlRef

from ._chain_helpers import make_reach_chain


def _f(check_id="GHA-001", passed=False, severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Example finding"),
        severity=severity,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description=kw.get("description", "Something is wrong."),
        recommendation=kw.get("recommendation", "Fix it."),
        passed=passed,
        controls=kw.get("controls", []),
        cwe=kw.get("cwe", []),
    )


def _score():
    return {
        "grade": "C",
        "score": 60,
        "summary": {
            "CRITICAL": {"passed": 0, "failed": 1},
            "HIGH":     {"passed": 2, "failed": 1},
        },
    }


class TestProviderMap:
    """The filter dropdown is populated from _provider_for(); any
    prefix that falls through to 'other' becomes invisible in the UI.
    Guard against future rule families silently dropping out of the map.
    """

    # Every prefix we scan today — add here when a new rule family lands.
    # The assertion below enforces that the runtime map covers at least
    # this set, so adding a GCB-NNN / TF-NNN etc. doesn't bitrot the UI.
    # Synced with the live ``pipeline_check/core/checks/`` rule directories
    # plus the cross-cutting families (TAINT-NNN dataflow engine, INGEST-*
    # multi-scanner SARIF). Chain check_ids (``AC-NNN`` / ``XPC-NNN``)
    # render in their own panel, not the findings table, so they
    # deliberately don't need a prefix-map entry.
    _KNOWN_PREFIXES = {
        # CI-provider families
        "GHA", "GL", "BB", "ADO", "JF", "CC", "GCB",
        "BK", "DR", "TKN", "ARGO",
        # AWS pipeline-services rule family
        "CB", "CP", "CD", "IAM", "S3", "ECR", "PBAC",
        "CT", "CWL", "CW", "EB", "SM", "SSM", "KMS",
        "CA", "CCM", "LMB", "SIGN",
        # IaC providers
        "TF", "CF", "CFN",
        # Container / runtime providers
        "DF", "K8S", "HELM",
        # OCI image manifests + attestation content (same provider)
        "OCI", "ATTEST",
        # SCM posture (governance via the GitHub REST API)
        "SCM",
        # Cross-cutting families
        "TAINT",   # dataflow taint engine across multiple providers
        "INGEST",  # external SARIF ingest (Trivy / Checkov / …)
    }

    def test_every_known_prefix_maps_somewhere(self):
        missing = self._KNOWN_PREFIXES - set(_PROVIDER_PREFIXES)
        assert not missing, (
            f"Prefixes {missing} are not in _PROVIDER_PREFIXES — "
            "findings with those IDs will collapse to the 'other' "
            "bucket in the HTML filter and be unreachable."
        )

    @pytest.mark.parametrize("check_id,expected", [
        ("GCB-001",  "cloudbuild"),
        ("CFN-012",  "cloudformation"),
        ("CF-012",   "cloudformation"),
        ("SIGN-001", "aws"),
        ("LMB-003",  "aws"),
        ("CA-002",   "aws"),
        ("CCM-001",  "aws"),
        ("CWL-002",  "aws"),
        # Container / runtime providers (added in the v0.5 expansion).
        ("DF-002",   "dockerfile"),
        ("K8S-013",  "kubernetes"),
        ("HELM-002", "helm"),
        # OCI manifests + attestation content share the OCI bucket.
        ("OCI-002",  "oci"),
        ("ATTEST-001", "oci"),
        # SCM posture (GitHub API).
        ("SCM-001",  "scm"),
        # Other CI providers.
        ("BK-001",   "buildkite"),
        ("DR-007",   "drone"),
        ("TKN-006",  "tekton"),
        ("ARGO-007", "argo"),
        # Cross-cutting families.
        ("TAINT-006", "taint"),
        # INGEST checks carry the source tool slug as the second
        # segment (``INGEST-trivy-CVE-2024-1234``); the prefix split
        # only consumes ``INGEST``.
        ("INGEST-trivy-CVE-2024-1234", "ingest"),
        ("INGEST-checkov-CKV2_AWS_61", "ingest"),
        ("XYZ-999",  "other"),  # unknown still falls back
    ])
    def test_provider_for_mapping(self, check_id, expected):
        assert _provider_for(check_id) == expected


class TestSmoke:
    def test_returns_well_formed_html(self):
        html = report_html([_f()], _score())
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "Pipeline-Check" in html

    def test_all_findings_rendered_as_rows(self):
        findings = [
            _f(check_id="GHA-001"),
            _f(check_id="IAM-002", severity=Severity.CRITICAL),
            _f(check_id="CB-005", passed=True),
        ]
        html = report_html(findings, _score())
        # Each check_id appears at least once (in its own row).
        for f in findings:
            assert f.check_id in html

    def test_output_file_is_written(self, tmp_path):
        out = tmp_path / "report.html"
        report_html([_f()], _score(), output_path=str(out))
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text(encoding="utf-8")


class TestDeepLinkAnchors:
    def test_each_row_has_a_stable_id(self):
        html = report_html([_f(check_id="GHA-001", resource=".github/workflows/ci.yml")], _score())
        # ID is ``finding-<lowercased check>-<slug>``.
        assert 'id="finding-gha-001-' in html

    def test_anchor_slug_escapes_path_characters(self):
        html = report_html([_f(check_id="S3-001", resource="s3://bucket/sub path")], _score())
        # Slashes, colons, and spaces collapse to dashes; the resulting
        # slug must be a valid URL fragment (no bare slashes or spaces).
        m = re.search(r'id="(finding-s3-001-[^"]*)"', html)
        assert m is not None
        slug = m.group(1)
        assert " " not in slug
        assert "/" not in slug

    def test_anchor_unique_across_rows_with_same_check(self):
        findings = [
            _f(check_id="GHA-001", resource="a.yml"),
            _f(check_id="GHA-001", resource="b.yml"),
        ]
        html = report_html(findings, _score())
        ids = re.findall(r'<tr id="(finding-[^"]*)"', html)
        assert len(ids) == 2
        assert len(set(ids)) == 2, f"Duplicate finding anchors: {ids}"


class TestInteractivity:
    """The interactive JS lives inline in the HTML. Assert the shape of
    that script so a refactor can't silently remove functionality.
    """

    def _html(self):
        return report_html([_f()], _score())

    def test_theme_honours_os_preference(self):
        html = self._html()
        assert "prefers-color-scheme: dark" in html
        assert "localStorage" in html
        assert "pipelinecheck.theme" in html

    def test_filter_state_syncs_to_url(self):
        html = self._html()
        # Hydrate + serialize round-trip.
        assert "URLSearchParams" in html
        assert "history.replaceState" in html

    def test_keyboard_shortcut_wired(self):
        html = self._html()
        # `/` focuses the filter; `Escape` clears it.
        assert "e.key === '/'" in html
        assert "e.key === 'Escape'" in html

    def test_expand_and_collapse_buttons_present(self):
        html = self._html()
        assert 'id="f-expand"' in html
        assert 'id="f-collapse"' in html

    def test_print_media_rules_present(self):
        html = self._html()
        assert "@media print" in html
        # Filter bar is hidden in print view.
        assert ".filter-bar" in html and "display: none" in html


class TestControlsPropagation:
    def test_kebab_case_control_ids_render(self):
        finding = _f(controls=[
            ControlRef(
                standard="openssf_scorecard",
                standard_title="OpenSSF Scorecard",
                control_id="Dangerous-Workflow",
                control_title="No dangerous patterns",
            ),
        ])
        html = report_html([finding], _score())
        assert "Dangerous-Workflow" in html
        # The standard slug drives the Standard filter dropdown.
        assert 'data-standards="openssf_scorecard"' in html


class TestFreeTextHaystack:
    """The free-text filter searches the per-row ``data-haystack``
    attribute. Make sure the haystack actually includes the fields a
    user would search for: description text and compliance control
    IDs / titles. Searches that return nothing because the haystack
    excludes the relevant field are a real UX regression."""

    def test_haystack_includes_check_id_title_and_resource(self):
        f = _f(
            check_id="GHA-001",
            title="Action not pinned",
            resource=".github/workflows/ci.yml",
        )
        html = report_html([f], _score())
        # Every row stamps its haystack into ``data-haystack``;
        # search the rendered HTML for the lowercased blob.
        assert "data-haystack=" in html
        assert "gha-001" in html.lower()
        assert "action not pinned" in html.lower()
        assert ".github/workflows/ci.yml" in html.lower()

    def test_haystack_includes_description(self):
        """Searching for a phrase from the description must match
        even when the row's ``<details>`` block isn't expanded."""
        f = _f(description="exfiltrates credentials via memdump endpoint")
        html = report_html([f], _score())
        m = re.search(r'data-haystack="([^"]+)"', html)
        assert m is not None
        haystack = m.group(1)
        assert "memdump" in haystack
        assert "credentials" in haystack

    def test_haystack_includes_control_ids(self):
        """Searching for an OWASP / NIST / Scorecard control ID
        should match the row even though the IDs render only inside
        the expanded detail panel."""
        f = _f(controls=[
            ControlRef(
                standard="owasp_cicd_top_10",
                standard_title="OWASP CI/CD Top 10",
                control_id="CICD-SEC-3",
                control_title="Dependency Chain Abuse",
            ),
        ])
        html = report_html([f], _score())
        m = re.search(r'data-haystack="([^"]+)"', html)
        assert m is not None
        haystack = m.group(1)
        assert "cicd-sec-3" in haystack
        assert "dependency chain abuse" in haystack


class TestAnchorHashTruncation:
    """Long resource paths get a truncated slug + 8-char hash so
    two paths sharing a 60-char prefix don't collide on the same
    deep-link anchor. Without the hash, ``slug[:60]`` would map both
    to the same fragment ID."""

    def test_anchor_includes_hash_suffix_when_slug_is_long(self):
        long_resource = (
            "infrastructure/terraform/modules/networking/very/deep/"
            "nested/path/that/exceeds/sixty/characters/foo.tf"
        )
        f = _f(check_id="TF-001", resource=long_resource)
        html = report_html([f], _score())
        m = re.search(r'<tr id="(finding-tf-001-[^"]*)"', html)
        assert m is not None
        anchor = m.group(1)
        # Truncated slug body is at most 50 chars, then a dash, then
        # an 8-hex-digit hash. Total slug fits in 60 chars so the URL
        # fragment stays manageable.
        # check_id portion ``finding-tf-001-`` is 15 chars, slug is up
        # to 59 (50 + dash + 8); total under 80.
        assert len(anchor) < 80
        # Hash suffix is 8 lowercase hex digits.
        assert re.search(r"-[0-9a-f]{8}$", anchor) is not None

    def test_anchor_distinct_for_paths_sharing_long_prefix(self):
        """The whole point of the hash suffix: two long paths that
        share a 60-char prefix must produce distinct anchors."""
        common_prefix = "a/" * 35  # 70 chars before the unique tail
        f1 = _f(check_id="TF-001", resource=common_prefix + "foo.tf")
        f2 = _f(check_id="TF-001", resource=common_prefix + "bar.tf")
        html = report_html([f1, f2], _score())
        anchors = re.findall(r'<tr id="(finding-tf-001-[^"]*)"', html)
        assert len(anchors) == 2
        assert anchors[0] != anchors[1], (
            f"hash truncation should break collisions but produced "
            f"duplicate anchors: {anchors}"
        )

    def test_anchor_unchanged_for_short_resources(self):
        """Short slugs aren't hashed — keeps the URL fragment
        readable when the resource is e.g. a single workflow file
        name."""
        f = _f(check_id="GHA-001", resource=".github/workflows/ci.yml")
        html = report_html([f], _score())
        m = re.search(r'<tr id="(finding-gha-001-[^"]*)"', html)
        assert m is not None
        anchor = m.group(1)
        # Short slug: no 8-hex-digit suffix.
        assert re.search(r"-[0-9a-f]{8}$", anchor) is None


class TestProofOfExploit:
    """Per the ``Rule.exploit_example`` field: when a finding fails
    AND carries an exploit snippet, the HTML drawer shows it under a
    "Proof of exploit" heading inside a ``<pre>`` block. Passing
    findings should not surface the snippet (they're not exploitable
    by definition)."""

    def test_renders_exploit_for_failing_finding(self):
        f = _f(
            check_id="GHA-001",
            passed=False,
        )
        f.exploit_example = (
            "# Tag-pinned action triggers the upstream-rewrite class.\n"
            "- uses: tj-actions/changed-files@v45"
        )
        html = report_html([f], _score())
        assert "Proof of exploit" in html
        assert "tj-actions/changed-files@v45" in html
        # Pre-formatted block, not a paragraph reflow.
        assert "<pre" in html and "white-space:pre-wrap" in html

    def test_skips_exploit_for_passing_finding(self):
        """A rule that passes can still carry an exploit_example on
        its RULE definition, but it's misleading to render the
        attack snippet for a finding that didn't actually fire."""
        f = _f(
            check_id="GHA-001",
            passed=True,
        )
        f.exploit_example = "echo 'this should not render'"
        html = report_html([f], _score())
        assert "Proof of exploit" not in html

    def test_silent_when_no_exploit_set(self):
        f = _f(check_id="GHA-024", passed=False)
        html = report_html([f], _score())
        assert "Proof of exploit" not in html


class TestChainsPanel:
    """The Attack Chains panel renders before the findings table when
    the Scanner produced any chain matches. Verify the panel hits
    every metadata field a chain card carries (severity-tinted
    border, MITRE ATT&CK, kill-chain phase, references, triggers,
    recommendation)."""

    def _chain(self, **overrides):
        from pipeline_check.core.chains.base import Chain
        from pipeline_check.core.checks.base import Confidence
        defaults = {
            "chain_id": "XPC-008",
            "title": "Unreviewed source ships mutable runtime image",
            "severity": Severity.HIGH,
            "confidence": Confidence.HIGH,
            "summary": (
                "Default branch is unprotected AND the Dockerfile "
                "pulls its base image by floating tag."
            ),
            "narrative": (
                "1. SCM-001 fires on the unprotected branch.\n"
                "2. DF-001 fires on the FROM tag.\n"
                "3. Composite: insider can land tampered FROM."
            ),
            "mitre_attack": ["T1195.002", "T1525"],
            "kill_chain_phase": (
                "supply-chain (insider source change -> mutable "
                "upstream ingestion at build-time)"
            ),
            "triggering_check_ids": ["SCM-001", "DF-001"],
            "triggering_findings": [],
            "resources": ["github:org/repo", "Dockerfile"],
            "references": [
                "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1",
            ],
            "recommendation": "Pin the FROM AND add branch protection.",
        }
        defaults.update(overrides)
        return Chain(**defaults)

    def test_panel_renders_when_chains_present(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        assert "Attack Chains" in html
        assert "XPC-008" in html
        assert "Unreviewed source ships mutable runtime image" in html

    def test_panel_omitted_when_no_chains(self):
        html = report_html([_f()], _score(), chains=[])
        assert "Attack Chains" not in html

    def test_chain_card_uses_severity_tinted_border(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        # HIGH severity → orange #fd7e14 in _SEVERITY_COLOR.
        assert "border-left-color:#fd7e14" in html

    def test_mitre_techniques_render(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        assert "MITRE ATT&amp;CK" in html
        assert "T1195.002" in html
        assert "T1525" in html

    def test_kill_chain_phase_renders(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        assert "Kill chain:" in html
        assert "supply-chain" in html

    def test_triggering_check_ids_render_as_codes(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        assert "Triggering checks:" in html
        # Both leg IDs appear as <code> tags inside the chain card.
        assert "SCM-001" in html
        assert "DF-001" in html

    def test_references_render_as_links(self):
        html = report_html([_f()], _score(), chains=[self._chain()])
        assert 'href="https://owasp.org' in html
        # External-link safety attributes.
        assert "noopener" in html

    def test_chain_uses_class_based_styling(self):
        """Refactor lock-in: chain card markup must use the CSS
        classes (``chain-card``, ``chain-card__head``, …) rather
        than reverting to inline styles. Catches regressions where
        a styling tweak silently re-inlines the block."""
        html = report_html([_f()], _score(), chains=[self._chain()])
        # Match each class as a token rather than as the full
        # ``class="..."`` attribute, so multi-class attrs
        # (``class="chain-card__line chain-card__triggers"``) still
        # satisfy the assertion. The verbatim form would miss any
        # element that combines a layout class with the semantic one.
        for cls in (
            "chain-card",
            "chain-card__head",
            "chain-card__title",
            "chain-card__narrative",
            "chain-card__triggers",
        ):
            found = any(
                token in html
                for token in (
                    f' {cls} ',
                    f'"{cls} ',
                    f' {cls}"',
                    f'"{cls}"',
                )
            )
            assert found, f"missing chain-card CSS class: {cls}"


class TestClipboardFallback:
    """The copy-ignore button must work both on HTTPS (via
    ``navigator.clipboard``) AND on ``file://`` (via the
    ``execCommand('copy')`` fallback). Chrome blocks the modern
    Clipboard API on the file: origin, which is the dominant
    local-report viewing case."""

    def test_script_includes_clipboard_fallback(self):
        html = report_html([_f()], _score())
        # Modern path is still attempted first.
        assert "navigator.clipboard" in html
        # Fallback path: textarea + execCommand.
        assert "execCommand" in html
        assert "createElement('textarea')" in html

    def test_script_uses_secure_context_check(self):
        """The fallback decision keys off ``window.isSecureContext``
        rather than blindly trying ``navigator.clipboard``, which
        would raise a TypeError on file:// in some browsers."""
        html = report_html([_f()], _score())
        assert "isSecureContext" in html

    def test_script_surfaces_copy_failed_state(self):
        """When both paths fail, the button text changes to
        ``copy failed`` so the user knows to copy manually rather
        than assuming the rule landed."""
        html = report_html([_f()], _score())
        assert "copy failed" in html


class TestDarkModeContrast:
    """The dark-mode token block tunes ``--light-muted`` for WCAG
    AA contrast on the dark background. Catches a regression where
    a future tweak drops the muted text below 4.5:1."""

    def test_dark_muted_token_meets_contrast_floor(self):
        html = report_html([_f()], _score())
        # The bumped value (#a0a0c0) lands at ~5.1:1 on the dark
        # background; assert the token isn't reverted to the prior
        # #8888aa (which was right at the 4.5 threshold).
        assert "--light-muted: #a0a0c0" in html
        assert "--light-muted: #8888aa" not in html


class TestStickyHeaderOffset:
    """The findings-table sticky header offset must accommodate the
    filter bar's full height (which wraps on narrow screens). Uses a
    CSS custom property so the offset can be tweaked per-breakpoint
    without scattering pixel literals through the rule block."""

    def test_sticky_offset_uses_css_variable(self):
        html = report_html([_f()], _score())
        assert "--filter-bar-h" in html
        # The findings-table header rule consults the custom prop.
        assert "top: var(--filter-bar-h)" in html

    def test_sticky_offset_breakpoints_present(self):
        """Narrow viewports (mobile / split-pane) need a larger
        offset because the filter bar wraps to multiple rows."""
        html = report_html([_f()], _score())
        assert "@media (max-width: 900px)" in html
        assert "@media (max-width: 600px)" in html


class TestReachabilityBadge:
    """The weak shared-job co-location tier must not borrow the proven
    dataflow tier's confident "confirmed" badge."""

    def test_dataflow_tier_confirmed(self):
        html = report_html(
            [_f()], _score(), chains=[make_reach_chain(via_dataflow=True)]
        )
        assert "Reachability confirmed (dataflow)" in html
        assert "Co-located (unverified)" not in html

    def test_structural_tier_confirmed(self):
        html = report_html(
            [_f()], _score(),
            chains=[make_reach_chain(via_dataflow=False, via_structural=True)],
        )
        assert "Reachability confirmed (structural)" in html
        assert "Co-located (unverified)" not in html

    def test_shared_job_tier_colocated_not_confirmed(self):
        html = report_html(
            [_f()], _score(), chains=[make_reach_chain(via_dataflow=False)]
        )
        assert "Co-located (unverified)" in html
        assert "Reachability confirmed" not in html
