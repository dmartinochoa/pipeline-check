"""Tests for the STRIDE threat-model reporter.

Covers three layers:

1. ``stride_for_finding`` STRIDE classification policy: every
   OWASP control maps to the documented STRIDE codes; CWE
   refinements prepend correctly; defaults handle uncategorized
   findings.
2. ``report_threatmodel`` reporter output: structural sections
   present, inventory rendered, chains rendered, risk-register
   capped at 25, escaping handles ``|`` / newlines.
3. CLI integration: ``--output threatmodel`` produces the
   document and writes to ``--output-file`` when given.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)
from pipeline_check.core.inventory import Component
from pipeline_check.core.scorer import ScoreResult, score
from pipeline_check.core.standards.base import ControlRef
from pipeline_check.core.threatmodel_reporter import (
    STRIDE,
    report_threatmodel,
    stride_for_finding,
)


def _ctrl(control_id: str) -> ControlRef:
    return ControlRef(
        standard="owasp_cicd_top_10",
        standard_title="OWASP Top 10 CI/CD Security Risks",
        control_id=control_id,
        control_title="(test)",
    )


def _finding(
    *,
    check_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    passed: bool = False,
    owasp: tuple[str, ...] = (),
    cwe: tuple[str, ...] = (),
    resource: str = "tests/example.yml",
    title: str = "test",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        resource=resource,
        description="test",
        recommendation="rotate / fix / pin",
        passed=passed,
        controls=[_ctrl(c) for c in owasp],
        cwe=list(cwe),
        confidence=Confidence.HIGH,
    )


# ── stride_for_finding ──────────────────────────────────────────────


class TestStrideClassification:
    @pytest.mark.parametrize(
        "owasp, expected_primary",
        [
            ("CICD-SEC-1",  "T"),  # flow-control bypass
            ("CICD-SEC-2",  "S"),  # IAM
            ("CICD-SEC-3",  "T"),  # dep chain
            ("CICD-SEC-4",  "T"),  # PPE
            ("CICD-SEC-5",  "E"),  # PBAC
            ("CICD-SEC-6",  "I"),  # creds
            ("CICD-SEC-7",  "E"),  # config
            ("CICD-SEC-8",  "T"),  # 3rd party
            ("CICD-SEC-9",  "T"),  # artifact integrity
            ("CICD-SEC-10", "R"),  # logging
        ],
    )
    def test_owasp_to_stride_primary(self, owasp, expected_primary):
        f = _finding(owasp=(owasp,))
        codes = stride_for_finding(f)
        assert codes[0] == expected_primary

    def test_owasp_with_two_categories_unions(self):
        # CICD-SEC-2 -> (S, E); CICD-SEC-6 -> (I, S). Union order
        # preserved with no dupes.
        f = _finding(owasp=("CICD-SEC-2", "CICD-SEC-6"))
        codes = stride_for_finding(f)
        assert codes[0] == "S"  # first OWASP wins primary slot
        assert "E" in codes
        assert "I" in codes
        assert len(set(codes)) == len(codes)

    def test_cwe_prepends_to_head(self):
        # CICD-SEC-7 -> (E, D), but CWE-200 (info disclosure)
        # prepends "I" so the primary classification is now
        # Information Disclosure regardless of the OWASP fallback.
        f = _finding(owasp=("CICD-SEC-7",), cwe=("CWE-200",))
        codes = stride_for_finding(f)
        assert codes[0] == "I"
        assert "E" in codes
        assert "D" in codes

    def test_cwe_no_op_when_already_primary(self):
        # CWE-200 -> "I", and OWASP CICD-SEC-6 already lists "I"
        # first. No duplication, no demotion.
        f = _finding(owasp=("CICD-SEC-6",), cwe=("CWE-200",))
        codes = stride_for_finding(f)
        assert codes[0] == "I"
        assert codes.count("I") == 1

    def test_default_when_no_owasp_no_cwe(self):
        f = _finding(owasp=(), cwe=())
        codes = stride_for_finding(f)
        # CI/CD failure modes are most often Tampering; that's the
        # documented default.
        assert codes == ("T",)

    def test_unknown_owasp_id_falls_through_to_default(self):
        # An ID that isn't in the OWASP -> STRIDE table shouldn't
        # crash; should fall through to the default classification.
        f = _finding(owasp=("CICD-SEC-99",))
        codes = stride_for_finding(f)
        assert codes == ("T",)

    def test_cwe_287_authentication_maps_to_spoofing(self):
        f = _finding(owasp=(), cwe=("CWE-287",))
        codes = stride_for_finding(f)
        assert codes[0] == "S"

    def test_cwe_400_dos_maps_to_d(self):
        f = _finding(owasp=(), cwe=("CWE-400",))
        codes = stride_for_finding(f)
        assert codes[0] == "D"

    def test_cwe_778_repudiation_maps_to_r(self):
        f = _finding(owasp=(), cwe=("CWE-778",))
        codes = stride_for_finding(f)
        assert codes[0] == "R"


# ── report_threatmodel ──────────────────────────────────────────────


def _score() -> ScoreResult:
    return score([])


class TestReporterStructure:
    def test_minimum_structure_sections(self):
        out = report_threatmodel([], _score())
        # Every documented section header is present.
        for header in (
            "# Threat Model",
            "## Scope",
            "## Trust boundaries",
            "## Assets",
            "## STRIDE analysis",
            "## Implemented controls",
            "## Risk register",
            "## Methodology",
        ):
            assert header in out, f"missing header: {header}"

    def test_every_stride_category_renders_subsection(self):
        out = report_threatmodel([], _score())
        for code, cat in STRIDE.items():
            assert f"### {code} -- {cat.name}" in out

    def test_no_findings_no_open_risks_message(self):
        out = report_threatmodel([], _score())
        assert "_No open risks" in out

    def test_failing_finding_shows_in_correct_category(self):
        # CICD-SEC-3 -> Tampering primary.
        f = _finding(
            check_id="GHA-001", severity=Severity.HIGH,
            owasp=("CICD-SEC-3",),
            title="Action not pinned to commit SHA",
        )
        out = report_threatmodel([f], score([f]))
        # Header + table row both visible, in the Tampering section.
        tampering_idx = out.index("### T -- Tampering")
        # The next category header.
        next_header_idx = out.index("### R -- Repudiation")
        slice_ = out[tampering_idx:next_header_idx]
        assert "GHA-001" in slice_
        assert "Action not pinned to commit SHA" in slice_

    def test_passing_finding_omitted_from_risk_register(self):
        f = _finding(
            check_id="GHA-001",
            owasp=("CICD-SEC-3",),
            passed=True,
        )
        out = report_threatmodel([f], score([f]))
        # The risk register only counts failures.
        register_idx = out.index("## Risk register")
        register_slice = out[register_idx:]
        assert "_No open risks" in register_slice

    def test_passing_finding_increments_implemented_controls_table(self):
        f = _finding(
            check_id="GHA-001",
            owasp=("CICD-SEC-3",),
            passed=True,
        )
        out = report_threatmodel([f], score([f]))
        impl_idx = out.index("## Implemented controls")
        next_idx = out.index("## Risk register")
        impl_slice = out[impl_idx:next_idx]
        # Tampering row should show "1".
        assert "Tampering (T) | 1" in impl_slice

    def test_inventory_section_lists_components(self):
        components = [
            Component(
                provider="github", type="workflow",
                identifier="ci.yml",
                source=".github/workflows/ci.yml",
            ),
            Component(
                provider="github", type="workflow",
                identifier="release.yml",
                source=".github/workflows/release.yml",
            ),
        ]
        out = report_threatmodel(
            [], _score(), inventory=components,
        )
        assert "### github / workflow (2)" in out
        assert "ci.yml" in out
        assert "release.yml" in out

    def test_inventory_empty_emits_friendly_placeholder(self):
        out = report_threatmodel([], _score(), inventory=[])
        assert "_No inventory captured" in out

    def test_trust_boundaries_emit_for_github(self):
        components = [
            Component(provider="github", type="workflow", identifier="ci"),
        ]
        out = report_threatmodel([], _score(), inventory=components)
        assert "Pull-request author -> CI runner" in out

    def test_trust_boundaries_emit_for_aws(self):
        components = [
            Component(provider="aws", type="iam_role", identifier="r"),
        ]
        out = report_threatmodel([], _score(), inventory=components)
        assert "CI identity -> cloud account" in out

    def test_risk_register_caps_at_25(self):
        many = [
            _finding(
                check_id=f"X-{n:03d}",
                owasp=("CICD-SEC-3",),
                resource=f"f{n}.yml",
            )
            for n in range(1, 31)
        ]
        out = report_threatmodel(many, score(many))
        register_idx = out.index("## Risk register")
        register_slice = out[register_idx:]
        # 25 rows + header rows. Look for the truncation breadcrumb.
        assert "+5 more failing finding(s) not shown" in register_slice

    def test_repeated_check_id_groups_into_one_threat_row(self):
        # Three findings, all GHA-001, on three different files.
        # The STRIDE section's threat table should collapse to one
        # row with affected=3.
        repeats = [
            _finding(
                check_id="GHA-001",
                owasp=("CICD-SEC-3",),
                resource=f"wf{n}.yml",
            )
            for n in range(3)
        ]
        out = report_threatmodel(repeats, score(repeats))
        tampering_idx = out.index("### T -- Tampering")
        next_idx = out.index("### R -- Repudiation")
        slice_ = out[tampering_idx:next_idx]
        # Exactly one row, affected count is 3.
        assert slice_.count("`GHA-001`") == 1
        assert "| 3 |" in slice_

    def test_pipe_in_title_is_escaped(self):
        f = _finding(
            check_id="X-001",
            owasp=("CICD-SEC-3",),
            title="bad | very bad",
        )
        out = report_threatmodel([f], score([f]))
        # Pipe escaped so the table row stays well-formed.
        assert "bad \\| very bad" in out

    def test_chains_section_only_when_chains_provided(self):
        out_no = report_threatmodel([], _score())
        assert "## Attack chains" not in out_no


# ── CLI integration ─────────────────────────────────────────────────


class TestCliIntegration:
    def test_threatmodel_output_to_stdout(self, tmp_path: Path):
        # A minimal GitLab CI doc that fires a couple of rules.
        gl = tmp_path / ".gitlab-ci.yml"
        gl.write_text(
            "image: python:latest\n"
            "stages: [test]\n"
            "build:\n"
            "  stage: test\n"
            "  script:\n"
            "    - echo Building ${CI_COMMIT_TITLE}\n"
        )
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--gitlab-path", str(gl),
                "--output", "threatmodel",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        # Document landed on stdout.
        assert "# Threat Model" in result.stdout
        assert "## STRIDE analysis" in result.stdout
        # GL-002 (script injection) should land in Tampering.
        tampering_idx = result.stdout.index("### T -- Tampering")
        next_idx = result.stdout.index("### R -- Repudiation")
        assert "GL-002" in result.stdout[tampering_idx:next_idx]

    def test_threatmodel_output_to_file(self, tmp_path: Path):
        gl = tmp_path / ".gitlab-ci.yml"
        gl.write_text(
            "image: python:latest\n"
            "stages: [test]\n"
            "build:\n"
            "  stage: test\n"
            "  script:\n"
            "    - make\n"
        )
        out_file = tmp_path / "threats.md"
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--gitlab-path", str(gl),
                "--output", "threatmodel",
                "--output-file", str(out_file),
            ],
        )
        assert result.exit_code in (0, 1), result.output
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "# Threat Model" in content
        # Stderr breadcrumb confirms file write.
        assert "Threat-model report written to" in result.output

    def test_threatmodel_implies_inventory(self, tmp_path: Path):
        # Without ``--inventory`` the GitLab provider would normally
        # emit no inventory. ``--output threatmodel`` should turn it
        # on automatically so the Assets section is populated.
        gl = tmp_path / ".gitlab-ci.yml"
        gl.write_text(
            "image: alpine:3.18\n"
            "stages: [test]\n"
            "build:\n"
            "  stage: test\n"
            "  script: [make]\n"
        )
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--gitlab-path", str(gl),
                "--output", "threatmodel",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        # The Assets section must NOT show the empty-inventory
        # placeholder, because threatmodel mode auto-enabled
        # inventory.
        assets_idx = result.stdout.index("## Assets")
        stride_idx = result.stdout.index("## STRIDE analysis")
        assets_slice = result.stdout[assets_idx:stride_idx]
        assert "_No inventory captured" not in assets_slice
        assert "gitlab / pipeline" in assets_slice

    def test_json_output_unchanged_by_threatmodel_addition(
        self, tmp_path: Path,
    ):
        # Sanity: adding the threatmodel format shouldn't have
        # broken any other output. Smoke-test JSON.
        gl = tmp_path / ".gitlab-ci.yml"
        gl.write_text(
            "image: alpine:3.18\n"
            "stages: [test]\n"
            "build:\n"
            "  stage: test\n"
            "  script: [make]\n"
        )
        result = CliRunner().invoke(
            scan,
            [
                "--pipeline", "gitlab",
                "--gitlab-path", str(gl),
                "--output", "json",
            ],
        )
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        assert "score" in payload
        assert "findings" in payload
