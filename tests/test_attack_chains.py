"""Tests for the attack-chain detection engine and the rules under
``pipeline_check.core.chains``."""
from __future__ import annotations

import json

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import chains as chains_pkg
from pipeline_check.core.chains.base import (
    Chain,
    failing,
    group_by_resource,
    has_failing,
    min_confidence,
)
from pipeline_check.core.checks.base import Confidence, Finding, Severity
from pipeline_check.core.gate import GateConfig, evaluate_gate

# ── Synthetic finding factory ─────────────────────────────────────────


def _f(
    check_id: str,
    resource: str,
    *,
    passed: bool = False,
    confidence: Confidence = Confidence.HIGH,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"{check_id} title",
        severity=severity,
        resource=resource,
        description="",
        recommendation="",
        passed=passed,
        confidence=confidence,
    )


# ── base.py helpers ──────────────────────────────────────────────────


class TestHelpers:
    def test_failing_filters_by_check_id_and_passed_flag(self):
        a = _f("X-1", "r1")
        b = _f("X-2", "r1")
        c = _f("X-1", "r2", passed=True)
        d = _f("X-3", "r1")
        out = failing([a, b, c, d], "X-1", "X-2")
        assert a in out and b in out
        assert c not in out  # passed
        assert d not in out  # different check_id

    def test_has_failing_simple(self):
        assert has_failing([_f("A", "r")], "A") is True
        assert has_failing([_f("A", "r", passed=True)], "A") is False
        assert has_failing([_f("A", "r")], "B") is False

    def test_group_by_resource_keeps_only_complete_groups(self):
        """A resource with only one of the required check IDs is dropped."""
        full = [_f("A", "r1"), _f("B", "r1")]   # both
        partial = [_f("A", "r2")]                # only A
        groups = group_by_resource(full + partial, ["A", "B"])
        assert "r1" in groups
        assert "r2" not in groups
        assert set(groups["r1"]) == {"A", "B"}

    def test_group_by_resource_ignores_passed(self):
        groups = group_by_resource(
            [_f("A", "r1", passed=True), _f("B", "r1")],
            ["A", "B"],
        )
        assert groups == {}

    def test_min_confidence_returns_lowest(self):
        a = _f("A", "r", confidence=Confidence.HIGH)
        b = _f("B", "r", confidence=Confidence.LOW)
        c = _f("C", "r", confidence=Confidence.MEDIUM)
        assert min_confidence([a, b, c]) is Confidence.LOW

    def test_min_confidence_empty_list_defaults_high(self):
        # Defensive: an empty list shouldn't crash callers; HIGH is the
        # sensible default since "no evidence" can't lower confidence.
        assert min_confidence([]) is Confidence.HIGH


# ── Engine ──────────────────────────────────────────────────────────


class TestEngine:
    def test_list_rules_discovers_all_chains(self):
        rule_ids = {r.id for r in chains_pkg.list_rules()}
        # Lock the current set so additions are an explicit decision.
        assert rule_ids == {
            "AC-001", "AC-002", "AC-003", "AC-004",
            "AC-005", "AC-006", "AC-007", "AC-008",
            "AC-009", "AC-010", "AC-011", "AC-012",
            "AC-013", "AC-014", "AC-015", "AC-016",
            "AC-017", "AC-018", "AC-019",
        }

    def test_evaluate_empty_findings_returns_empty(self):
        assert chains_pkg.evaluate([]) == []

    def test_evaluate_filters_by_enabled(self):
        # Even with matching findings, an empty enabled set yields nothing.
        wf = ".github/workflows/x.yml"
        findings = [_f("GHA-002", wf), _f("GHA-005", wf)]
        assert chains_pkg.evaluate(findings, enabled=set()) == []
        # And the same findings DO produce AC-001 when AC-001 is enabled.
        out = chains_pkg.evaluate(findings, enabled={"AC-001"})
        assert [c.chain_id for c in out] == ["AC-001"]

    def test_evaluate_results_sorted_by_chain_id(self):
        wf = ".github/workflows/x.yml"
        findings = [
            _f("GHA-001", wf), _f("GHA-002", wf), _f("GHA-005", wf),
        ]
        out = chains_pkg.evaluate(findings)
        # AC-001 (GHA-002 + GHA-005) and AC-003 (GHA-001 + GHA-005)
        # both fire — must come back in deterministic ID order.
        ids = [c.chain_id for c in out]
        assert ids == sorted(ids)

    def test_chain_to_dict_round_trip_is_json_serialisable(self):
        wf = ".github/workflows/x.yml"
        findings = [_f("GHA-002", wf), _f("GHA-005", wf)]
        chain = chains_pkg.evaluate(findings)[0]
        # to_dict must round-trip through json without failing.
        json.dumps(chain.to_dict())
        d = chain.to_dict()
        assert d["chain_id"] == "AC-001"
        assert d["severity"] == "CRITICAL"
        assert "T1078.004" in d["mitre_attack"]
        assert d["triggering_check_ids"] == ["GHA-002", "GHA-005"]


# ── Per-chain positive / negative ────────────────────────────────────


class TestChainAC001:
    """AC-001 — Fork-PR Credential Theft."""

    def test_fires_when_both_legs_on_same_workflow(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-005", wf)])
        assert any(c.chain_id == "AC-001" for c in out)
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.severity is Severity.CRITICAL
        assert ac1.resources == [wf]
        assert "T1078.004" in ac1.mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-005", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-001" for c in out)

    def test_does_not_fire_when_one_leg_passed(self):
        wf = ".github/workflows/x.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, passed=True), _f("GHA-005", wf),
        ])
        assert not any(c.chain_id == "AC-001" for c in out)

    def test_confidence_inherits_minimum(self):
        wf = ".github/workflows/x.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, confidence=Confidence.HIGH),
            _f("GHA-005", wf, confidence=Confidence.LOW),
        ])
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.confidence is Confidence.LOW


class TestChainAC005:
    """AC-005 — cross-provider; resources may differ between legs."""

    def test_fires_across_providers(self):
        out = chains_pkg.evaluate([
            _f("GHA-006", ".github/workflows/build.yml"),
            _f("CP-001", "arn:aws:codepipeline:us-east-1:1:pipeline/x"),
        ])
        assert any(c.chain_id == "AC-005" for c in out)

    def test_does_not_fire_without_deploy_leg(self):
        out = chains_pkg.evaluate([_f("GHA-006", ".github/workflows/build.yml")])
        assert not any(c.chain_id == "AC-005" for c in out)

    def test_does_not_fire_without_build_leg(self):
        out = chains_pkg.evaluate([_f("CP-001", "arn:aws:codepipeline:.../x")])
        assert not any(c.chain_id == "AC-005" for c in out)


class TestChainAC002:
    """AC-002 — Script Injection to Unprotected Deploy."""

    def test_fires_when_both_legs_on_same_workflow(self):
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([_f("GHA-003", wf), _f("GHA-014", wf)])
        ac2 = [c for c in out if c.chain_id == "AC-002"]
        assert len(ac2) == 1
        assert ac2[0].severity is Severity.CRITICAL
        assert "T1190" in ac2[0].mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-003", ".github/workflows/a.yml"),
            _f("GHA-014", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-002" for c in out)


class TestChainAC004:
    """AC-004 — Self-Hosted Runner Persistent Foothold."""

    def test_fires_with_pull_request_target_and_non_ephemeral_runner(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-012", wf)])
        ac4 = [c for c in out if c.chain_id == "AC-004"]
        assert len(ac4) == 1
        assert "T1543" in ac4[0].mitre_attack


class TestChainAC006:
    """AC-006 — Cache Poisoning via Untrusted Trigger."""

    def test_fires_with_pull_request_target_and_cache_key_issue(self):
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-011", wf)])
        ac6 = [c for c in out if c.chain_id == "AC-006"]
        assert len(ac6) == 1
        assert ac6[0].severity is Severity.HIGH


class TestChainAC008:
    """AC-008 — Dependency Confusion Window."""

    def test_fires_with_no_lockfile_and_integrity_bypass(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([_f("GHA-021", wf), _f("GHA-029", wf)])
        ac8 = [c for c in out if c.chain_id == "AC-008"]
        assert len(ac8) == 1
        assert "T1195.001" in ac8[0].mitre_attack


class TestChainAC007:
    """AC-007 — IAM PrivEsc via CodeBuild (AWS-specific, multi-resource)."""

    def test_fires_with_cb002_plus_iam002(self):
        out = chains_pkg.evaluate([
            _f("CB-002", "arn:aws:codebuild:.../proj"),
            _f("IAM-002", "arn:aws:iam::1:role/build"),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        assert ac7[0].severity is Severity.CRITICAL

    def test_fires_with_cb002_plus_iam004(self):
        out = chains_pkg.evaluate([
            _f("CB-002", "arn:aws:codebuild:.../proj"),
            _f("IAM-004", "arn:aws:iam::1:role/build"),
        ])
        assert any(c.chain_id == "AC-007" for c in out)

    def test_does_not_fire_without_iam_leg(self):
        out = chains_pkg.evaluate([_f("CB-002", "arn:aws:codebuild:.../proj")])
        assert not any(c.chain_id == "AC-007" for c in out)


class TestChainAC009:
    """AC-009 — Supply Chain Repo Poisoning."""

    def test_fires_with_all_three_legs_on_same_workflow(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-001", wf),
            _f("GHA-002", wf),
            _f("GHA-008", wf),
        ])
        ac9 = [c for c in out if c.chain_id == "AC-009"]
        assert len(ac9) == 1
        assert ac9[0].severity is Severity.CRITICAL
        assert "T1195.002" in ac9[0].mitre_attack

    def test_does_not_fire_with_only_two_legs(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-001", wf),
            _f("GHA-002", wf),
        ])
        assert not any(c.chain_id == "AC-009" for c in out)

    def test_does_not_fire_when_legs_are_on_different_workflows(self):
        # Three legs across three workflows is not the same threat as
        # all three on one workflow — the chain should ignore.
        out = chains_pkg.evaluate([
            _f("GHA-001", ".github/workflows/a.yml"),
            _f("GHA-002", ".github/workflows/b.yml"),
            _f("GHA-008", ".github/workflows/c.yml"),
        ])
        assert not any(c.chain_id == "AC-009" for c in out)


class TestChainAC010:
    """AC-010 — Self-Hosted Runner Environment Exfiltration."""

    def test_fires_with_self_hosted_plus_curl_pipe(self):
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([
            _f("GHA-012", wf),
            _f("GHA-016", wf),
        ])
        ac10 = [c for c in out if c.chain_id == "AC-010"]
        assert len(ac10) == 1
        assert ac10[0].severity is Severity.CRITICAL

    def test_fires_with_self_hosted_plus_token_persistence(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-012", wf),
            _f("GHA-019", wf),
        ])
        assert any(c.chain_id == "AC-010" for c in out)

    def test_fires_with_all_three_legs(self):
        # Both secondary legs on the same runner is the strongest case.
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([
            _f("GHA-012", wf),
            _f("GHA-016", wf),
            _f("GHA-019", wf),
        ])
        ac10 = [c for c in out if c.chain_id == "AC-010"]
        assert len(ac10) == 1
        # Both legs surface in the chain's narrative.
        assert "GHA-016" in ac10[0].triggering_check_ids
        assert "GHA-019" in ac10[0].triggering_check_ids

    def test_does_not_fire_without_self_hosted_leg(self):
        # curl-pipe alone is bad but isn't this chain — AC-010 needs
        # the persistence vector that a non-ephemeral runner gives.
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([_f("GHA-016", wf), _f("GHA-019", wf)])
        assert not any(c.chain_id == "AC-010" for c in out)

    def test_does_not_fire_with_only_self_hosted(self):
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([_f("GHA-012", wf)])
        assert not any(c.chain_id == "AC-010" for c in out)


class TestChainAC011:
    """AC-011 — Kubernetes Cluster Takeover via hostPath + cluster-admin."""

    K8S_RESOURCE = "kubernetes/manifests"

    def test_fires_with_hostpath_and_cluster_admin(self):
        out = chains_pkg.evaluate([
            _f("K8S-013", self.K8S_RESOURCE),
            _f("K8S-020", self.K8S_RESOURCE),
        ])
        ac11 = [c for c in out if c.chain_id == "AC-011"]
        assert len(ac11) == 1
        assert ac11[0].severity is Severity.CRITICAL
        assert "K8S-013" in ac11[0].triggering_check_ids
        assert "K8S-020" in ac11[0].triggering_check_ids

    def test_does_not_fire_without_hostpath(self):
        # cluster-admin alone is bad but doesn't give the node escape
        # leg this chain models.
        out = chains_pkg.evaluate([_f("K8S-020", self.K8S_RESOURCE)])
        assert not any(c.chain_id == "AC-011" for c in out)

    def test_does_not_fire_without_cluster_admin(self):
        # hostPath alone gives node escape but not cluster API authority.
        out = chains_pkg.evaluate([_f("K8S-013", self.K8S_RESOURCE)])
        assert not any(c.chain_id == "AC-011" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        # Findings present but green — neither rule actually triggered.
        out = chains_pkg.evaluate([
            _f("K8S-013", self.K8S_RESOURCE, passed=True),
            _f("K8S-020", self.K8S_RESOURCE, passed=True),
        ])
        assert not any(c.chain_id == "AC-011" for c in out)


class TestChainAC012:
    """AC-012 — Reusable Workflow Secret Exfiltration."""

    WF = ".github/workflows/release.yml"

    def test_fires_when_both_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-025", self.WF), _f("GHA-034", self.WF),
        ])
        ac12 = [c for c in out if c.chain_id == "AC-012"]
        assert len(ac12) == 1
        assert ac12[0].severity is Severity.CRITICAL
        assert ac12[0].resources == [self.WF]
        assert "T1552.001" in ac12[0].mitre_attack
        assert ac12[0].triggering_check_ids == ["GHA-025", "GHA-034"]

    def test_does_not_fire_when_legs_on_different_workflows(self):
        # GHA-025 in one workflow + GHA-034 in another isn't the same
        # call site; the secret surface differs per call.
        out = chains_pkg.evaluate([
            _f("GHA-025", ".github/workflows/a.yml"),
            _f("GHA-034", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-012" for c in out)

    def test_does_not_fire_when_only_pinning_leg_fails(self):
        # An unpinned reusable-workflow ref without ``secrets: inherit``
        # is risky (GHA-025 fires) but the call has explicit secrets,
        # so the chain's exfiltration leg is missing.
        out = chains_pkg.evaluate([_f("GHA-025", self.WF)])
        assert not any(c.chain_id == "AC-012" for c in out)

    def test_does_not_fire_when_only_inherit_leg_fails(self):
        # ``secrets: inherit`` against a SHA-pinned callee is a
        # least-privilege issue (GHA-034 fires) but a tag-move attack
        # isn't possible — pin is immutable.
        out = chains_pkg.evaluate([_f("GHA-034", self.WF)])
        assert not any(c.chain_id == "AC-012" for c in out)

    def test_confidence_inherits_minimum(self):
        out = chains_pkg.evaluate([
            _f("GHA-025", self.WF, confidence=Confidence.HIGH),
            _f("GHA-034", self.WF, confidence=Confidence.MEDIUM),
        ])
        ac12 = next(c for c in out if c.chain_id == "AC-012")
        assert ac12.confidence is Confidence.MEDIUM


class TestChainAC013:
    """AC-013 — Caller-Controlled Runner with Token Persistence."""

    WF = ".github/workflows/release.yml"

    def test_fires_when_both_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF), _f("GHA-019", self.WF),
        ])
        ac13 = [c for c in out if c.chain_id == "AC-013"]
        assert len(ac13) == 1
        assert ac13[0].severity is Severity.CRITICAL
        assert ac13[0].resources == [self.WF]
        assert "T1552.001" in ac13[0].mitre_attack
        assert "T1078" in ac13[0].mitre_attack
        assert ac13[0].triggering_check_ids == ["GHA-036", "GHA-019"]

    def test_does_not_fire_when_legs_on_different_workflows(self):
        # GHA-036 in workflow A and GHA-019 in workflow B aren't the
        # same execution — picking a runner in one place doesn't get
        # you the token persisted somewhere else.
        out = chains_pkg.evaluate([
            _f("GHA-036", ".github/workflows/a.yml"),
            _f("GHA-019", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-013" for c in out)

    def test_does_not_fire_when_only_targeting_leg_fails(self):
        # Caller picks the runner but the workflow doesn't write
        # tokens to disk — the targeting risk stands alone, not as
        # the AC-013 chain.
        out = chains_pkg.evaluate([_f("GHA-036", self.WF)])
        assert not any(c.chain_id == "AC-013" for c in out)

    def test_does_not_fire_when_only_persistence_leg_fails(self):
        # Token written to disk but the runner is hard-coded — token
        # persistence on a known runner is its own risk (GHA-019),
        # not the routing-attack chain.
        out = chains_pkg.evaluate([_f("GHA-019", self.WF)])
        assert not any(c.chain_id == "AC-013" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        # Findings present but green — neither rule actually triggered.
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF, passed=True),
            _f("GHA-019", self.WF, passed=True),
        ])
        assert not any(c.chain_id == "AC-013" for c in out)

    def test_confidence_inherits_minimum(self):
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF, confidence=Confidence.HIGH),
            _f("GHA-019", self.WF, confidence=Confidence.LOW),
        ])
        ac13 = next(c for c in out if c.chain_id == "AC-013")
        assert ac13.confidence is Confidence.LOW


class TestChainAC014:
    """AC-014 — Caller-Controlled Runner with Token Persistence (GitLab)."""

    PIPELINE = ".gitlab-ci.yml"

    def test_fires_when_both_legs_on_same_pipeline(self):
        out = chains_pkg.evaluate([
            _f("GL-032", self.PIPELINE), _f("GL-020", self.PIPELINE),
        ])
        ac14 = [c for c in out if c.chain_id == "AC-014"]
        assert len(ac14) == 1
        assert ac14[0].severity is Severity.CRITICAL
        assert ac14[0].resources == [self.PIPELINE]
        assert "T1552.001" in ac14[0].mitre_attack
        assert "T1078" in ac14[0].mitre_attack
        assert ac14[0].triggering_check_ids == ["GL-032", "GL-020"]

    def test_does_not_fire_when_legs_on_different_pipelines(self):
        out = chains_pkg.evaluate([
            _f("GL-032", "a.gitlab-ci.yml"),
            _f("GL-020", "b.gitlab-ci.yml"),
        ])
        assert not any(c.chain_id == "AC-014" for c in out)

    def test_does_not_fire_when_only_targeting_leg_fails(self):
        out = chains_pkg.evaluate([_f("GL-032", self.PIPELINE)])
        assert not any(c.chain_id == "AC-014" for c in out)

    def test_does_not_fire_when_only_persistence_leg_fails(self):
        out = chains_pkg.evaluate([_f("GL-020", self.PIPELINE)])
        assert not any(c.chain_id == "AC-014" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GL-032", self.PIPELINE, passed=True),
            _f("GL-020", self.PIPELINE, passed=True),
        ])
        assert not any(c.chain_id == "AC-014" for c in out)

    def test_confidence_inherits_minimum(self):
        out = chains_pkg.evaluate([
            _f("GL-032", self.PIPELINE, confidence=Confidence.HIGH),
            _f("GL-020", self.PIPELINE, confidence=Confidence.MEDIUM),
        ])
        ac14 = next(c for c in out if c.chain_id == "AC-014")
        assert ac14.confidence is Confidence.MEDIUM


class TestChainAC015:
    """AC-015 — Helm chart-supply-chain takeover."""

    HELM_RESOURCE = "helm/charts"

    def test_fires_when_all_three_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE),
            _f("HELM-002", self.HELM_RESOURCE),
            _f("HELM-003", self.HELM_RESOURCE),
        ])
        ac15 = [c for c in out if c.chain_id == "AC-015"]
        assert len(ac15) == 1
        chain = ac15[0]
        assert chain.severity is Severity.CRITICAL
        assert set(chain.triggering_check_ids) == {"HELM-001", "HELM-002", "HELM-003"}
        # MITRE technique IDs surface for downstream MITRE ATT&CK
        # mappings; T1195.002 is the load-bearing one for the supply-
        # chain story this chain narrates.
        assert "T1195.002" in chain.mitre_attack
        assert "T1557" in chain.mitre_attack  # adversary-in-the-middle leg

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE),
            _f("HELM-002", self.HELM_RESOURCE),
            _f("HELM-003", self.HELM_RESOURCE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-015")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase

    def test_does_not_fire_without_helm001(self):
        # v2 chart with unlocked + plaintext deps still loses, but
        # the chain is specifically about the schema-lock-out leg.
        out = chains_pkg.evaluate([
            _f("HELM-002", self.HELM_RESOURCE),
            _f("HELM-003", self.HELM_RESOURCE),
        ])
        assert not any(c.chain_id == "AC-015" for c in out)

    def test_does_not_fire_without_helm002(self):
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE),
            _f("HELM-003", self.HELM_RESOURCE),
        ])
        assert not any(c.chain_id == "AC-015" for c in out)

    def test_does_not_fire_without_helm003(self):
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE),
            _f("HELM-002", self.HELM_RESOURCE),
        ])
        assert not any(c.chain_id == "AC-015" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        # Findings present but green — none of the rules actually
        # tripped. The chain should stay quiet rather than light up
        # on the ID alone.
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE, passed=True),
            _f("HELM-002", self.HELM_RESOURCE, passed=True),
            _f("HELM-003", self.HELM_RESOURCE, passed=True),
        ])
        assert not any(c.chain_id == "AC-015" for c in out)

    def test_confidence_picks_lowest_leg(self):
        # min_confidence: a HIGH leg + a HIGH leg + a LOW leg yields
        # LOW, since the chain is only as confident as its shakiest
        # finding.
        out = chains_pkg.evaluate([
            _f("HELM-001", self.HELM_RESOURCE, confidence=Confidence.HIGH),
            _f("HELM-002", self.HELM_RESOURCE, confidence=Confidence.HIGH),
            _f("HELM-003", self.HELM_RESOURCE, confidence=Confidence.LOW),
        ])
        chain = next(c for c in out if c.chain_id == "AC-015")
        assert chain.confidence is Confidence.LOW


class TestChainAC016:
    """AC-016 — OIDC role drift: ungated GitHub trust + wildcard AWS authority."""

    WF = ".github/workflows/release.yml"
    ROLE = "arn:aws:iam::123456789012:role/ci-deploy"

    def test_fires_when_both_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("IAM-002", self.ROLE),
        ])
        ac16 = [c for c in out if c.chain_id == "AC-016"]
        assert len(ac16) == 1
        assert ac16[0].severity is Severity.CRITICAL
        assert set(ac16[0].triggering_check_ids) == {"GHA-030", "IAM-002"}
        assert "T1078.004" in ac16[0].mitre_attack
        assert "T1556" in ac16[0].mitre_attack

    def test_does_not_fire_without_gha030(self):
        # IAM wildcard is bad on its own; this chain is specifically
        # about the OIDC trust-side gap that lets fork PRs reach it.
        out = chains_pkg.evaluate([_f("IAM-002", self.ROLE)])
        assert not any(c.chain_id == "AC-016" for c in out)

    def test_does_not_fire_without_iam002(self):
        out = chains_pkg.evaluate([_f("GHA-030", self.WF)])
        assert not any(c.chain_id == "AC-016" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF, passed=True),
            _f("IAM-002", self.ROLE, passed=True),
        ])
        assert not any(c.chain_id == "AC-016" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("IAM-002", self.ROLE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-016")
        assert "credential-access" in chain.kill_chain_phase
        assert "privilege-escalation" in chain.kill_chain_phase


class TestChainAC017:
    """AC-017 — Build cache poisoning that lands on a mutable ECR tag."""

    WF = ".github/workflows/release.yml"
    REPO = "myapp"

    def test_fires_when_both_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("GHA-011", self.WF),
            _f("ECR-002", self.REPO),
        ])
        ac17 = [c for c in out if c.chain_id == "AC-017"]
        assert len(ac17) == 1
        assert ac17[0].severity is Severity.HIGH
        assert set(ac17[0].triggering_check_ids) == {"GHA-011", "ECR-002"}
        # T1195.001 is the supply-chain dependency-compromise leg.
        assert "T1195.001" in ac17[0].mitre_attack

    def test_does_not_fire_without_gha011(self):
        # Mutable ECR tags alone are a posture issue but the chain
        # is about the cache-poisoned-build feeding them.
        out = chains_pkg.evaluate([_f("ECR-002", self.REPO)])
        assert not any(c.chain_id == "AC-017" for c in out)

    def test_does_not_fire_without_ecr002(self):
        out = chains_pkg.evaluate([_f("GHA-011", self.WF)])
        assert not any(c.chain_id == "AC-017" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GHA-011", self.WF, passed=True),
            _f("ECR-002", self.REPO, passed=True),
        ])
        assert not any(c.chain_id == "AC-017" for c in out)

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("GHA-011", self.WF, confidence=Confidence.HIGH),
            _f("ECR-002", self.REPO, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-017")
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC018:
    """AC-018 — unpinned action lands on deploy job with no env gate."""

    WF = ".github/workflows/release.yml"
    OTHER_WF = ".github/workflows/lint.yml"

    def test_fires_when_both_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF),
            _f("GHA-014", self.WF),
        ])
        ac18 = [c for c in out if c.chain_id == "AC-018"]
        assert len(ac18) == 1
        assert ac18[0].severity is Severity.CRITICAL
        assert set(ac18[0].triggering_check_ids) == {"GHA-001", "GHA-014"}
        assert "T1195.002" in ac18[0].mitre_attack

    def test_does_not_fire_on_different_workflows(self):
        # Each leg on a different workflow doesn't compose — the
        # chain narrative claims same-workflow co-occurrence.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF),
            _f("GHA-014", self.OTHER_WF),
        ])
        assert not any(c.chain_id == "AC-018" for c in out)

    def test_does_not_fire_without_gha001(self):
        out = chains_pkg.evaluate([_f("GHA-014", self.WF)])
        assert not any(c.chain_id == "AC-018" for c in out)

    def test_does_not_fire_without_gha014(self):
        out = chains_pkg.evaluate([_f("GHA-001", self.WF)])
        assert not any(c.chain_id == "AC-018" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, passed=True),
            _f("GHA-014", self.WF, passed=True),
        ])
        assert not any(c.chain_id == "AC-018" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF), _f("GHA-014", self.WF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-018")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase


class TestChainAC019:
    """AC-019 — Lambda env-secret meets PassRole *."""

    LAMBDA = "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
    ROLE = "arn:aws:iam::123456789012:role/ci-deploy"

    def test_fires_when_both_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("LMB-003", self.LAMBDA),
            _f("IAM-004", self.ROLE),
        ])
        ac19 = [c for c in out if c.chain_id == "AC-019"]
        assert len(ac19) == 1
        assert ac19[0].severity is Severity.CRITICAL
        assert "T1552.001" in ac19[0].mitre_attack
        assert "T1098.003" in ac19[0].mitre_attack

    def test_does_not_fire_without_lmb003(self):
        out = chains_pkg.evaluate([_f("IAM-004", self.ROLE)])
        assert not any(c.chain_id == "AC-019" for c in out)

    def test_does_not_fire_without_iam004(self):
        out = chains_pkg.evaluate([_f("LMB-003", self.LAMBDA)])
        assert not any(c.chain_id == "AC-019" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("LMB-003", self.LAMBDA, passed=True),
            _f("IAM-004", self.ROLE, passed=True),
        ])
        assert not any(c.chain_id == "AC-019" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("LMB-003", self.LAMBDA),
            _f("IAM-004", self.ROLE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-019")
        assert "credential-access" in chain.kill_chain_phase
        assert "privilege-escalation" in chain.kill_chain_phase

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("LMB-003", self.LAMBDA, confidence=Confidence.HIGH),
            _f("IAM-004", self.ROLE, confidence=Confidence.LOW),
        ])
        chain = next(c for c in out if c.chain_id == "AC-019")
        assert chain.confidence is Confidence.LOW


# ── Gate integration ─────────────────────────────────────────────────


class TestGate:
    def _chain(self, chain_id="AC-001"):
        # Build a Chain object directly without re-evaluating; keeps the
        # gate test independent of rule predicates.
        f = _f("GHA-002", ".github/workflows/x.yml")
        return Chain(
            chain_id=chain_id, title="t", severity=Severity.CRITICAL,
            confidence=Confidence.HIGH, summary="", narrative="",
            mitre_attack=[], kill_chain_phase="", triggering_check_ids=[],
            triggering_findings=[f], resources=["x"], references=[],
            recommendation="",
        )

    def test_fail_on_any_chain_trips(self):
        cfg = GateConfig(fail_on_any_chain=True)
        result = evaluate_gate(
            [], {"grade": "A"}, cfg, chains=[self._chain()],
        )
        assert result.passed is False
        assert result.tripped_chains
        assert any("--fail-on-any-chain" in r for r in result.reasons)

    def test_fail_on_chain_specific_id_trips(self):
        cfg = GateConfig(fail_on_chains={"AC-001"})
        result = evaluate_gate(
            [], {"grade": "A"}, cfg,
            chains=[self._chain("AC-001"), self._chain("AC-008")],
        )
        assert result.passed is False
        # Only the named chain is in tripped_chains.
        assert {c.chain_id for c in result.tripped_chains} == {"AC-001"}

    def test_chain_gate_passes_when_no_chains(self):
        cfg = GateConfig(fail_on_any_chain=True)
        result = evaluate_gate([], {"grade": "A"}, cfg, chains=[])
        assert result.passed is True


# ── CLI ──────────────────────────────────────────────────────────────


class TestCLI:
    def test_list_chains_prints_all_ids(self):
        result = CliRunner().invoke(scan, ["--list-chains"])
        assert result.exit_code == 0
        for cid in ("AC-001", "AC-005", "AC-008"):
            assert cid in result.output

    def test_explain_chain_prints_summary(self):
        result = CliRunner().invoke(scan, ["--explain-chain", "AC-001"])
        assert result.exit_code == 0
        assert "AC-001" in result.output
        assert "Fork-PR" in result.output
        assert "MITRE ATT&CK" in result.output

    def test_explain_chain_unknown_id_exits_3_with_suggestion(self):
        result = CliRunner().invoke(scan, ["--explain-chain", "AC-999"])
        assert result.exit_code == 3

    def test_no_chains_in_json_output_when_disabled(self, tmp_path, monkeypatch):
        # Create a fixture workflow that triggers AC-001 — pull_request_target
        # checking out PR head + AWS keys in env.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "name: ci\n"
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
            "      AWS_SECRET_ACCESS_KEY: notarealsecret/notarealsecret/notarealsecret\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        monkeypatch.chdir(tmp_path)

        def _json_from_output(text: str) -> dict:
            # CliRunner merges stderr/stdout; the CLI emits ``[auto]``
            # and ``[scan]`` status lines to stderr before the JSON
            # body. Carve out the JSON object starting at the first
            # ``{`` and ending at the matching ``}``.
            i = text.index("{")
            return json.loads(text[i:])

        # With chains enabled (default): JSON should include a chains key.
        result = CliRunner().invoke(scan, ["-p", "github", "-o", "json"])
        payload = _json_from_output(result.output)
        assert "chains" in payload
        # With --no-chains: chains key omitted.
        result = CliRunner().invoke(
            scan, ["-p", "github", "-o", "json", "--no-chains"],
        )
        payload = _json_from_output(result.output)
        assert "chains" not in payload
