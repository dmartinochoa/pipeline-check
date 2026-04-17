"""Per-check end-to-end tests using realistic snippets.

For every workflow-provider check (60 total: 12 GHA + 12 GL + 10 BB +
13 ADO + 13 JF) this module exercises:

  1. an UNSAFE snippet sourced from real-world anti-patterns, and
     asserts the targeted check fires AND carries the expected OWASP
     and ESF (where mapped) ControlRefs.
  2. a SAFE snippet — usually the same shape with the fix applied —
     and asserts the targeted check passes.

Other checks may pass or fail on either snippet; the per-check tests
only assert behaviour for the targeted check_id. The broader sweep
in ``test_workflow_fixtures.py`` covers cross-check coordination on
the larger fixtures.

Snippet bodies live on disk under ``tests/fixtures/per_check/<provider>/``
so this file owns ONLY the metadata (which standards each finding
should map to). That separation lets the snippets be edited with
native YAML / Groovy syntax highlighting in any IDE, copy-pasted
from real workflows, and inspected without scrolling through
hundreds of triple-quoted Python strings.

Adding a check
--------------
1. Append a ``CheckCase`` to ``CASES`` below.
2. Drop two snippets at:
       tests/fixtures/per_check/<provider>/<check-id>.unsafe.<ext>
       tests/fixtures/per_check/<provider>/<check-id>.safe.<ext>
   where ``<ext>`` is ``yml`` for the YAML providers and
   ``jenkinsfile`` for Jenkins. The file extension determines the
   syntax highlighter the IDE picks.
3. The unsafe snippet must trigger the targeted check; the safe
   snippet must not.
4. ``expected_owasp`` is the primary OWASP CICD-SEC control. Add
   ``expected_esf`` if the check has an ESF mapping.

The provider context loader is selected automatically from the
check ID prefix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core import standards as standards_mod
from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks
from pipeline_check.core.checks.base import Finding
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks
from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.circleci.base import CircleCIContext
from pipeline_check.core.checks.circleci.pipelines import CircleCIPipelineChecks
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks

SNIPPET_ROOT = Path(__file__).parent / "fixtures" / "per_check"


# ──────────────────────────────────────────────────────────────────────
# Per-prefix wiring — provider context, check class, snippet extension.
# ──────────────────────────────────────────────────────────────────────


_PROVIDER_BY_PREFIX: dict[str, tuple[Any, Any, str, str]] = {
    # prefix -> (context_class, check_class, fixture-dir-name, extension)
    "GHA": (GitHubContext,    WorkflowChecks,           "github",    "yml"),
    "GL":  (GitLabContext,    GitLabPipelineChecks,     "gitlab",    "yml"),
    "BB":  (BitbucketContext, BitbucketPipelineChecks,  "bitbucket", "yml"),
    "ADO": (AzureContext,     AzurePipelineChecks,      "azure",     "yml"),
    "JF":  (JenkinsContext,   JenkinsfileChecks,        "jenkins",   "jenkinsfile"),
    "CC":  (CircleCIContext,  CircleCIPipelineChecks,   "circleci",  "yml"),
}


@dataclass(frozen=True)
class CheckCase:
    check_id: str
    expected_owasp: str
    expected_esf: tuple[str, ...] = field(default_factory=tuple)

    def _path(self, kind: str) -> Path:
        prefix = self.check_id.split("-", 1)[0]
        _, _, sub, ext = _PROVIDER_BY_PREFIX[prefix]
        return SNIPPET_ROOT / sub / f"{self.check_id}.{kind}.{ext}"

    @property
    def unsafe_path(self) -> Path:
        return self._path("unsafe")

    @property
    def safe_path(self) -> Path:
        return self._path("safe")


# ──────────────────────────────────────────────────────────────────────
# Test harness
# ──────────────────────────────────────────────────────────────────────


def _run_one_check(check_id: str, snippet_path: Path, tmp_path: Path) -> Finding:
    """Copy *snippet_path* into ``tmp_path``, scan with the right
    provider, return the finding for *check_id* with ControlRefs
    enriched (mirrors what the real Scanner does post-run)."""
    prefix = check_id.split("-", 1)[0]
    ctx_cls, check_cls, _, ext = _PROVIDER_BY_PREFIX[prefix]
    # Copy under a known filename in tmp_path so the loader can pick
    # it up regardless of the snippet's own basename.
    fname = "Jenkinsfile" if ext == "jenkinsfile" else "wf.yml"
    target = tmp_path / fname
    target.write_text(snippet_path.read_text(encoding="utf-8"), encoding="utf-8")
    ctx = ctx_cls.from_path(target)
    findings = check_cls(ctx).run()
    finding = next((f for f in findings if f.check_id == check_id), None)
    assert finding is not None, (
        f"check {check_id} produced no finding from {snippet_path}; "
        f"either the snippet is malformed or the check is mis-IDed."
    )
    active = standards_mod.resolve()
    finding.controls = standards_mod.resolve_for_check(check_id, active)
    return finding


def _assert_owasp(finding: Finding, expected: str) -> None:
    owasp = [
        c.control_id for c in finding.controls
        if c.standard == "owasp_cicd_top_10"
    ]
    assert expected in owasp, (
        f"{finding.check_id}: expected OWASP {expected} in controls, "
        f"got {owasp}"
    )


def _assert_esf(finding: Finding, expected: tuple[str, ...]) -> None:
    esf = [
        c.control_id for c in finding.controls
        if c.standard == "esf_supply_chain"
    ]
    for ctrl in expected:
        assert ctrl in esf, (
            f"{finding.check_id}: expected ESF {ctrl} in controls, got {esf}"
        )


# ──────────────────────────────────────────────────────────────────────
# Catalogue — one entry per workflow check.
# ──────────────────────────────────────────────────────────────────────
#
# The snippet bodies live on disk; this list owns only the metadata
# the assertions care about. Adding an entry here without dropping
# the matching snippet files makes ``_run_one_check`` raise
# ``FileNotFoundError``, which is caught by the catalogue-completeness
# guard at the bottom.

CASES: list[CheckCase] = [
    # ── GitHub Actions ───────────────────────────────────────────────
    CheckCase("GHA-001", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("GHA-002", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-D-BUILD-ENV")),
    CheckCase("GHA-003", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("GHA-004", "CICD-SEC-5", ("ESF-C-LEAST-PRIV",)),
    CheckCase("GHA-005", "CICD-SEC-6", ("ESF-D-TOKEN-HYGIENE",)),
    CheckCase("GHA-006", "CICD-SEC-9", ("ESF-D-SIGN-ARTIFACTS",)),
    CheckCase("GHA-007", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("GHA-008", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("GHA-009", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("GHA-010", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-PIN-DEPS")),
    CheckCase("GHA-011", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("GHA-012", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("GHA-013", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("GHA-014", "CICD-SEC-1", ("ESF-C-APPROVAL", "ESF-C-ENV-SEP")),
    CheckCase("GHA-015", "CICD-SEC-7", ("ESF-D-BUILD-TIMEOUT",)),
    CheckCase("GHA-016", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("GHA-017", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("GHA-018", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("GHA-019", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("GHA-020", "CICD-SEC-3", ("ESF-S-VULN-MGMT",)),
    CheckCase("GHA-021", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("GHA-022", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("GHA-023", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    # ── GitLab CI ────────────────────────────────────────────────────
    CheckCase("GL-001", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("GL-002", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("GL-003", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("GL-004", "CICD-SEC-1", ("ESF-C-APPROVAL", "ESF-C-ENV-SEP")),
    CheckCase("GL-005", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG")),
    CheckCase("GL-006", "CICD-SEC-9", ("ESF-D-SIGN-ARTIFACTS",)),
    CheckCase("GL-007", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("GL-008", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("GL-009", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE")),
    CheckCase("GL-010", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("GL-011", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-PIN-DEPS")),
    CheckCase("GL-012", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("GL-013", "CICD-SEC-6", ("ESF-D-TOKEN-HYGIENE",)),
    CheckCase("GL-014", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("GL-015", "CICD-SEC-7", ("ESF-D-BUILD-TIMEOUT",)),
    CheckCase("GL-016", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("GL-017", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("GL-018", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("GL-019", "CICD-SEC-3", ("ESF-S-VULN-MGMT",)),
    CheckCase("GL-020", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("GL-021", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("GL-022", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("GL-023", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    # ── Bitbucket Pipelines ──────────────────────────────────────────
    CheckCase("BB-001", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("BB-002", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("BB-003", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("BB-004", "CICD-SEC-1", ("ESF-C-APPROVAL", "ESF-C-ENV-SEP")),
    CheckCase("BB-005", "CICD-SEC-7", ("ESF-D-BUILD-TIMEOUT",)),
    CheckCase("BB-006", "CICD-SEC-9", ("ESF-D-SIGN-ARTIFACTS",)),
    CheckCase("BB-007", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("BB-008", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("BB-009", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE")),
    CheckCase("BB-010", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("BB-011", "CICD-SEC-6", ("ESF-D-TOKEN-HYGIENE",)),
    CheckCase("BB-012", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("BB-013", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("BB-014", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("BB-015", "CICD-SEC-3", ("ESF-S-VULN-MGMT",)),
    CheckCase("BB-016", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("BB-017", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("BB-018", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("BB-019", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("BB-020", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("BB-021", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("BB-022", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("BB-023", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    # ── Azure DevOps Pipelines ───────────────────────────────────────
    CheckCase("ADO-001", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("ADO-002", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("ADO-003", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("ADO-004", "CICD-SEC-1", ("ESF-C-APPROVAL", "ESF-C-ENV-SEP")),
    CheckCase("ADO-005", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG")),
    CheckCase("ADO-006", "CICD-SEC-9", ("ESF-D-SIGN-ARTIFACTS",)),
    CheckCase("ADO-007", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("ADO-008", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("ADO-009", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE")),
    CheckCase("ADO-010", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("ADO-011", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-PIN-DEPS")),
    CheckCase("ADO-012", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("ADO-013", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("ADO-014", "CICD-SEC-6", ("ESF-D-TOKEN-HYGIENE",)),
    CheckCase("ADO-015", "CICD-SEC-7", ("ESF-D-BUILD-TIMEOUT",)),
    CheckCase("ADO-016", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("ADO-017", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("ADO-018", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("ADO-019", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-PIN-DEPS")),
    CheckCase("ADO-020", "CICD-SEC-3", ("ESF-S-VULN-MGMT",)),
    CheckCase("ADO-021", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("ADO-022", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("ADO-023", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    # ── Jenkins ──────────────────────────────────────────────────────
    CheckCase("JF-001", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("JF-002", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("JF-003", "CICD-SEC-5", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("JF-004", "CICD-SEC-6", ("ESF-D-TOKEN-HYGIENE",)),
    CheckCase("JF-005", "CICD-SEC-1", ("ESF-C-APPROVAL",)),
    CheckCase("JF-006", "CICD-SEC-9", ("ESF-D-SIGN-ARTIFACTS",)),
    CheckCase("JF-007", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("JF-008", "CICD-SEC-6", ("ESF-D-SECRETS",)),
    CheckCase("JF-009", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE")),
    CheckCase("JF-010", "CICD-SEC-6", ("ESF-D-SECRETS", "ESF-D-TOKEN-HYGIENE")),
    CheckCase("JF-011", "CICD-SEC-10", ("ESF-D-BUILD-LOGS", "ESF-C-AUDIT")),
    CheckCase("JF-012", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("JF-013", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("JF-014", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    CheckCase("JF-015", "CICD-SEC-7", ("ESF-D-BUILD-TIMEOUT",)),
    CheckCase("JF-016", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("JF-017", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("JF-018", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("JF-019", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    CheckCase("JF-020", "CICD-SEC-3", ("ESF-S-VULN-MGMT",)),
    CheckCase("JF-021", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("JF-022", "CICD-SEC-3", ("ESF-S-PIN-DEPS",)),
    CheckCase("JF-023", "CICD-SEC-3", ("ESF-S-VERIFY-DEPS",)),
    CheckCase("JF-024", "CICD-SEC-1", ("ESF-C-APPROVAL",)),
    CheckCase("JF-025", "CICD-SEC-7", ("ESF-D-BUILD-ENV",)),
    CheckCase("JF-026", "CICD-SEC-4", ("ESF-C-APPROVAL",)),
    CheckCase("JF-027", "CICD-SEC-9", ("ESF-D-TAMPER",)),
    CheckCase("JF-028", "CICD-SEC-9", ("ESF-D-SBOM",)),
    # Category 1 — SLSA provenance attestation (6 providers)
    CheckCase("GHA-024", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("GL-024", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("BB-024", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("ADO-024", "CICD-SEC-9", ("ESF-D-SBOM",)),
    CheckCase("CC-024", "CICD-SEC-9", ("ESF-D-SBOM",)),
    # Category 2 — build cache poisoning
    CheckCase("CC-025", "CICD-SEC-4", ("ESF-D-INJECTION",)),
    # Category 3 — reusable-workflow / template pinning
    CheckCase("GHA-025", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    CheckCase("ADO-025", "CICD-SEC-3", ("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS")),
    # Category 4 — hermetic egress
    CheckCase("GHA-026", "CICD-SEC-7", ("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD")),
    # Malicious-activity indicators (Category 5)
    CheckCase("GHA-027", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("GL-025", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("BB-025", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("ADO-026", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("CC-026", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
    CheckCase("JF-029", "CICD-SEC-4", ("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS")),
]


# ──────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.check_id)
def test_unsafe_snippet_triggers_check_with_correct_standards(case, tmp_path):
    """The unsafe snippet at ``case.unsafe_path`` must produce a
    FAILING finding for the targeted check, and that finding must
    carry the expected OWASP (and ESF where mapped) ControlRefs."""
    f = _run_one_check(case.check_id, case.unsafe_path, tmp_path)
    assert f.passed is False, (
        f"{case.check_id}: unsafe snippet did NOT trigger the check.\n"
        f"--- snippet ({case.unsafe_path}) ---\n"
        + case.unsafe_path.read_text(encoding="utf-8")
    )
    _assert_owasp(f, case.expected_owasp)
    if case.expected_esf:
        _assert_esf(f, case.expected_esf)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.check_id)
def test_safe_snippet_does_not_trigger_check(case, tmp_path):
    """The safe snippet at ``case.safe_path`` must produce a PASSING
    finding for the targeted check. Other checks may pass or fail —
    we only assert behaviour for the targeted ID."""
    f = _run_one_check(case.check_id, case.safe_path, tmp_path)
    assert f.passed is True, (
        f"{case.check_id}: safe snippet triggered the check unexpectedly.\n"
        f"description: {f.description}\n"
        f"--- snippet ({case.safe_path}) ---\n"
        + case.safe_path.read_text(encoding="utf-8")
    )


def test_every_workflow_check_has_a_case():
    """Lock in that this catalogue stays in sync with the registered
    workflow checks. If a new check ships without an entry here, this
    test fails — forcing the author to write a real-example case."""
    expected_ids = (
        {f"GHA-{i:03d}" for i in range(1, 24)}
        | {f"GL-{i:03d}" for i in range(1, 24)}
        | {f"BB-{i:03d}" for i in range(1, 24)}
        | {f"ADO-{i:03d}" for i in range(1, 24)}
        | {f"JF-{i:03d}" for i in range(1, 24)}
    )
    covered = {c.check_id for c in CASES}
    missing = expected_ids - covered
    assert not missing, (
        f"per-check catalogue is missing entries for: {sorted(missing)}. "
        f"Add a CheckCase + snippet pair for each so future regressions "
        f"are caught."
    )


def test_every_case_has_both_snippet_files_on_disk():
    """A ``CheckCase`` without its two snippet files would surface as
    a confusing ``FileNotFoundError`` deep inside the test harness.
    Fail fast at collection time instead."""
    missing = []
    for case in CASES:
        if not case.unsafe_path.exists():
            missing.append(str(case.unsafe_path))
        if not case.safe_path.exists():
            missing.append(str(case.safe_path))
    assert not missing, (
        f"missing snippet files for {len(missing)} case(s):\n"
        + "\n".join(f"  - {m}" for m in missing)
    )
