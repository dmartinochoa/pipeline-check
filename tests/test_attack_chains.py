"""Tests for the attack-chain detection engine and the rules under
``pipeline_check.core.chains``."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import chains as chains_pkg
from pipeline_check.core.chains.base import (
    Chain,
    failing,
    group_by_anchor,
    group_by_resource,
    has_failing,
    min_confidence,
)
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    ResourceAnchor,
    Severity,
    TaintFlow,
)
from pipeline_check.core.gate import GateConfig, evaluate_gate

# ── Synthetic finding factory ─────────────────────────────────────────


def _f(
    check_id: str,
    resource: str,
    *,
    passed: bool = False,
    confidence: Confidence = Confidence.HIGH,
    severity: Severity = Severity.HIGH,
    job_anchors: tuple[str, ...] = (),
    path_evidence: tuple[str, ...] = (),
    resource_anchors: tuple[ResourceAnchor, ...] = (),
    taint_flows: tuple[TaintFlow, ...] = (),
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
        job_anchors=job_anchors,
        path_evidence=path_evidence,
        resource_anchors=resource_anchors,
        taint_flows=taint_flows,
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

    def test_group_by_anchor_intersects_on_identity(self):
        # Two findings reference the same IAM role ARN; group_by_anchor
        # composes them under that ARN as the key.
        role = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/deploy",
        )
        wf = _f("X-1", "wf.yml", resource_anchors=(role,))
        iam = _f("X-2", role.identity, resource_anchors=(role,))
        groups = group_by_anchor([wf, iam], ["X-1", "X-2"], "iam_role")
        assert set(groups) == {role.identity}
        assert set(groups[role.identity]) == {"X-1", "X-2"}

    def test_group_by_anchor_drops_partial_groups(self):
        # Only X-1 anchors on the role — not enough to form the group.
        role = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/deploy",
        )
        wf = _f("X-1", "wf.yml", resource_anchors=(role,))
        groups = group_by_anchor([wf], ["X-1", "X-2"], "iam_role")
        assert groups == {}

    def test_group_by_anchor_ignores_other_kinds(self):
        # A finding that anchors only an ecr_repo doesn't contribute
        # to an iam_role intersection.
        repo = ResourceAnchor(
            kind="ecr_repo",
            identity="123456789012.dkr.ecr.us-east-1.amazonaws.com/r",
        )
        role = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/deploy",
        )
        a = _f("X-1", "wf.yml", resource_anchors=(repo,))
        b = _f("X-2", role.identity, resource_anchors=(role,))
        groups = group_by_anchor([a, b], ["X-1", "X-2"], "iam_role")
        assert groups == {}

    def test_group_by_anchor_handles_multi_anchor_findings(self):
        # A workflow that references three IAM roles emits three
        # anchors; only the one that intersects with the IAM finding
        # contributes a group.
        roles = [
            ResourceAnchor(
                kind="iam_role",
                identity=f"arn:aws:iam::123456789012:role/r{i}",
            )
            for i in range(3)
        ]
        wf = _f("X-1", "wf.yml", resource_anchors=tuple(roles))
        iam = _f(
            "X-2", roles[1].identity, resource_anchors=(roles[1],),
        )
        groups = group_by_anchor([wf, iam], ["X-1", "X-2"], "iam_role")
        assert set(groups) == {roles[1].identity}

    def test_group_by_anchor_ignores_passed_findings(self):
        role = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/deploy",
        )
        groups = group_by_anchor(
            [
                _f("X-1", "wf.yml", passed=True, resource_anchors=(role,)),
                _f("X-2", role.identity, resource_anchors=(role,)),
            ],
            ["X-1", "X-2"],
            "iam_role",
        )
        assert groups == {}


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
            "AC-017", "AC-018", "AC-019", "AC-020",
            "AC-021", "AC-022", "AC-023", "AC-024",
            "AC-025", "AC-026", "AC-027", "AC-028", "AC-029",
            "AC-030", "AC-031", "AC-032", "AC-033", "AC-034",
            "AC-035", "AC-036", "AC-037", "AC-038", "AC-039",
            "XPC-001", "XPC-002", "XPC-003", "XPC-004", "XPC-005",
            "XPC-006", "XPC-007", "XPC-008", "XPC-009", "XPC-010",
            "CXPC-001", "CXPC-002", "CXPC-003", "CXPC-004",
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

    def test_broken_rule_logs_breadcrumb_and_keeps_running(self, caplog):
        # A buggy chain rule that raises must not abort the engine, but
        # it should leave a WARNING breadcrumb so the failure isn't
        # invisible. Inject one through the same cache the engine
        # populates after ``_discover()`` first runs.
        import logging

        from pipeline_check.core.chains import engine
        from pipeline_check.core.chains.base import ChainRule

        chains_pkg.evaluate([])  # populate cache
        bogus_rule = ChainRule(
            id="ZZ-BROKEN",
            title="raises on purpose",
            severity=Severity.HIGH,
            summary="x",
            triggering_check_ids=("GHA-002",),
        )

        def _explode(_findings):
            raise RuntimeError("intentional test failure")

        assert engine._RULES_CACHE is not None
        engine._RULES_CACHE.append((bogus_rule, _explode))
        try:
            with caplog.at_level(logging.WARNING, logger="pipeline_check.core.chains.engine"):
                chains_pkg.evaluate([
                    _f("GHA-002", ".github/workflows/x.yml"),
                ])
            # Engine kept going (legitimate AC-001 / AC-003 chains still
            # fire on the GHA-002 input), and the breadcrumb landed.
            assert any("ZZ-BROKEN" in r.message for r in caplog.records)
        finally:
            engine._RULES_CACHE.pop()

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

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, job_anchors=("publish",)),
            _f(
                "GHA-005",
                wf,
                job_anchors=("publish",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.confirmed_reachable is True
        assert "publish" in ac1.reachability_note
        assert ac1.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, job_anchors=("label",)),
            _f(
                "GHA-005",
                wf,
                job_anchors=("publish",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.confirmed_reachable is False
        assert ac1.reachability_note == ""
        assert ac1.confidence is Confidence.MEDIUM


class TestChainAC035:
    """AC-035 — AI agent is both reviewer and committer."""

    def test_fires_on_gha103_plus_gha104(self):
        wf = ".github/workflows/ai-review.yml"
        out = chains_pkg.evaluate([_f("GHA-103", wf), _f("GHA-104", wf)])
        ac = next((c for c in out if c.chain_id == "AC-035"), None)
        assert ac is not None
        assert ac.severity is Severity.CRITICAL
        assert ac.triggering_check_ids == ["GHA-103", "GHA-104"]
        assert ac.resources == [wf]

    def test_fires_on_gha103_plus_gha106(self):
        wf = ".github/workflows/ai-review.yml"
        out = chains_pkg.evaluate([_f("GHA-103", wf), _f("GHA-106", wf)])
        ac = next((c for c in out if c.chain_id == "AC-035"), None)
        assert ac is not None
        assert ac.triggering_check_ids == ["GHA-103", "GHA-106"]

    def test_dedupes_to_one_when_both_write_legs_present(self):
        wf = ".github/workflows/ai-review.yml"
        out = chains_pkg.evaluate([
            _f("GHA-103", wf), _f("GHA-104", wf), _f("GHA-106", wf),
        ])
        ac035 = [c for c in out if c.chain_id == "AC-035"]
        assert len(ac035) == 1
        # GHA-104 wins the dedupe (iterated first).
        assert ac035[0].triggering_check_ids == ["GHA-103", "GHA-104"]

    def test_does_not_fire_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-103", ".github/workflows/a.yml"),
            _f("GHA-106", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-035" for c in out)

    def test_does_not_fire_without_write_leg(self):
        wf = ".github/workflows/ai-review.yml"
        out = chains_pkg.evaluate([_f("GHA-103", wf)])
        assert not any(c.chain_id == "AC-035" for c in out)

    def test_does_not_fire_when_reviewer_leg_passed(self):
        wf = ".github/workflows/ai-review.yml"
        out = chains_pkg.evaluate([
            _f("GHA-103", wf, passed=True), _f("GHA-104", wf),
        ])
        assert not any(c.chain_id == "AC-035" for c in out)


class TestChainAC036:
    """AC-036 — untrusted-code execution with no egress containment."""

    def test_fires_on_injection_plus_no_egress(self):
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([_f("GHA-003", wf), _f("GHA-108", wf)])
        ac = next((c for c in out if c.chain_id == "AC-036"), None)
        assert ac is not None
        assert ac.severity is Severity.HIGH
        assert ac.triggering_check_ids == ["GHA-003", "GHA-108"]
        assert ac.resources == [wf]

    def test_fires_on_curlbash_plus_audit_mode(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-016", wf), _f("GHA-107", wf)])
        ac = next((c for c in out if c.chain_id == "AC-036"), None)
        assert ac is not None
        assert "GHA-016" in ac.triggering_check_ids
        assert "GHA-107" in ac.triggering_check_ids

    def test_confirmed_reachable_when_same_job(self):
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, job_anchors=("deploy",)),
            _f("GHA-108", wf, job_anchors=("deploy",)),
        ])
        ac = next((c for c in out if c.chain_id == "AC-036"), None)
        assert ac is not None
        assert ac.confirmed_reachable is True
        assert ac.confidence is Confidence.HIGH
        assert "deploy" in ac.reachability_note

    def test_unconfirmed_when_different_jobs(self):
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, job_anchors=("build",)),
            _f("GHA-108", wf, job_anchors=("release",)),
        ])
        ac = next((c for c in out if c.chain_id == "AC-036"), None)
        assert ac is not None
        assert ac.confirmed_reachable is False

    def test_does_not_fire_without_egress_leg(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-003", wf)])
        assert not any(c.chain_id == "AC-036" for c in out)

    def test_does_not_fire_without_exec_leg(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-108", wf)])
        assert not any(c.chain_id == "AC-036" for c in out)

    def test_does_not_fire_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-003", ".github/workflows/a.yml"),
            _f("GHA-108", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-036" for c in out)

    def test_does_not_fire_when_exec_leg_passed(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, passed=True), _f("GHA-108", wf),
        ])
        assert not any(c.chain_id == "AC-036" for c in out)


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

    def test_reachability_confirmed_when_image_anchor_matches(self):
        # GHA-006 emits the image its build pushes; GHA-014 emits the
        # image its deploy references. Same canonical identity ⇒
        # confirmed chain at HIGH with the image as the resource.
        img = ResourceAnchor(
            kind="oci_image", identity="ghcr.io/acme/app",
        )
        out = chains_pkg.evaluate([
            _f(
                "GHA-006", ".github/workflows/build.yml",
                resource_anchors=(img,),
            ),
            _f(
                "GHA-014", ".github/workflows/deploy.yml",
                resource_anchors=(img,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac5 = [c for c in out if c.chain_id == "AC-005"]
        assert len(ac5) == 1
        chain = ac5[0]
        assert chain.confirmed_reachable is True
        assert "ghcr.io/acme/app" in chain.reachability_note
        assert chain.resources == ["ghcr.io/acme/app"]
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_when_image_anchors_disjoint(self):
        # Build pushes app-a; deploy references app-b. Co-occurrence
        # fallback preserves the multi-provider signal.
        a = ResourceAnchor(kind="oci_image", identity="ghcr.io/acme/app-a")
        b = ResourceAnchor(kind="oci_image", identity="ghcr.io/acme/app-b")
        out = chains_pkg.evaluate([
            _f(
                "GHA-006", ".github/workflows/build.yml",
                resource_anchors=(a,),
            ),
            _f(
                "GHA-014", ".github/workflows/deploy.yml",
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac5 = [c for c in out if c.chain_id == "AC-005"]
        assert len(ac5) == 1
        chain = ac5[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM

    def test_one_confirmed_chain_per_image_identity(self):
        # Two build workflows push two different images; two deploy
        # workflows reference each. Expect two confirmed chains, one
        # per shared image.
        app_a = ResourceAnchor(kind="oci_image", identity="ghcr.io/acme/app-a")
        app_b = ResourceAnchor(kind="oci_image", identity="ghcr.io/acme/app-b")
        out = chains_pkg.evaluate([
            _f(
                "GHA-006", ".github/workflows/build-a.yml",
                resource_anchors=(app_a,),
            ),
            _f(
                "GHA-006", ".github/workflows/build-b.yml",
                resource_anchors=(app_b,),
            ),
            _f(
                "GHA-014", ".github/workflows/deploy-a.yml",
                resource_anchors=(app_a,),
            ),
            _f(
                "GHA-014", ".github/workflows/deploy-b.yml",
                resource_anchors=(app_b,),
            ),
        ])
        ac5 = [c for c in out if c.chain_id == "AC-005"]
        confirmed = [c for c in ac5 if c.confirmed_reachable]
        assert len(confirmed) == 2
        assert {c.resources[0] for c in confirmed} == {
            app_a.identity, app_b.identity,
        }

    @pytest.mark.parametrize(
        "build_id,build_path,deploy_id,deploy_path",
        [
            # Cross-provider confirmed pairs: build in one provider,
            # deploy in another, but the same image identity flows
            # between them via the oci_image anchor.
            ("GL-006",  ".gitlab-ci.yml",            "GHA-014", ".github/workflows/deploy.yml"),
            ("BB-006",  "bitbucket-pipelines.yml",   "GHA-014", ".github/workflows/deploy.yml"),
            ("ADO-006", "azure-pipelines.yml",       "GHA-014", ".github/workflows/deploy.yml"),
            ("CC-006",  ".circleci/config.yml",      "GHA-014", ".github/workflows/deploy.yml"),
            ("GCB-009", "cloudbuild.yaml",           "GHA-014", ".github/workflows/deploy.yml"),
            ("JF-006",  "Jenkinsfile",               "GHA-014", ".github/workflows/deploy.yml"),
            # Same shape with the deploy on each non-GHA provider too.
            ("GHA-006", ".github/workflows/build.yml", "GL-004",  ".gitlab-ci.yml"),
            ("GHA-006", ".github/workflows/build.yml", "BB-004",  "bitbucket-pipelines.yml"),
            ("GHA-006", ".github/workflows/build.yml", "ADO-004", "azure-pipelines.yml"),
            ("GHA-006", ".github/workflows/build.yml", "CC-009",  ".circleci/config.yml"),
            ("GHA-006", ".github/workflows/build.yml", "JF-005",  "Jenkinsfile"),
        ],
    )
    def test_reachability_confirmed_across_providers_via_oci_image(
        self, build_id, build_path, deploy_id, deploy_path,
    ):
        # Once every provider's leg rule emits oci_image anchors, the
        # cross-provider build → deploy pairing should confirm through
        # group_by_anchor for any (build_id, deploy_id) combination
        # AC-005 covers.
        img = ResourceAnchor(kind="oci_image", identity="ghcr.io/acme/app")
        out = chains_pkg.evaluate([
            _f(build_id, build_path, resource_anchors=(img,)),
            _f(deploy_id, deploy_path, resource_anchors=(img,)),
        ])
        ac5 = [c for c in out if c.chain_id == "AC-005"]
        confirmed = [c for c in ac5 if c.confirmed_reachable]
        assert len(confirmed) == 1
        assert confirmed[0].resources == ["ghcr.io/acme/app"]
        assert confirmed[0].confidence is Confidence.HIGH


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

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # GHA-003 fires in job ``release``, GHA-014 reports
        # ``release`` as an ungated deploy job. The intersection is
        # non-empty so the chain is confirmed reachable, with the
        # composite confidence promoted to HIGH.
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, job_anchors=("release",)),
            _f(
                "GHA-014",
                wf,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac2 = next(c for c in out if c.chain_id == "AC-002")
        assert ac2.confirmed_reachable is True
        assert "release" in ac2.reachability_note
        assert ac2.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # Two legs fire on the same workflow but in distinct jobs and
        # no taint propagation rule corroborates a cross-job hop.
        # The chain still fires (legacy behavior) but ``confirmed
        # _reachable`` is False and the confidence stays at the
        # weakest leg.
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, job_anchors=("triage",)),
            _f(
                "GHA-014",
                wf,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac2 = next(c for c in out if c.chain_id == "AC-002")
        assert ac2.confirmed_reachable is False
        assert ac2.reachability_note == ""
        assert ac2.confidence is Confidence.MEDIUM

    def test_taint_path_widens_injection_side_for_reachability(self):
        # GHA-003 fires only in ``extract``, but TAINT-002 reports a
        # cross-job path whose sink lands in ``release`` — the same
        # job GHA-014 names. The chain is reachable via the dataflow
        # hop even though GHA-003 alone wouldn't intersect.
        wf = ".github/workflows/deploy.yml"
        rendered_path = (
            "${{ github.event.issue.title }}@extract[0] -> "
            "steps.extract.outputs.title -> "
            "jobs.extract.outputs.title -> "
            "needs.extract.outputs.title -> "
            "sink@release[2](kubectl)"
        )
        out = chains_pkg.evaluate([
            _f("GHA-003", wf, job_anchors=("extract",)),
            _f(
                "TAINT-002",
                wf,
                job_anchors=("release",),
                path_evidence=(rendered_path,),
                taint_flows=(
                    TaintFlow(
                        source_job="extract",
                        sink_job="release",
                        rendered=rendered_path,
                    ),
                ),
            ),
            _f("GHA-014", wf, job_anchors=("release",)),
        ])
        ac2 = next(c for c in out if c.chain_id == "AC-002")
        assert ac2.confirmed_reachable is True
        # Phase-2: confirmed by a real source->sink taint path, not just
        # shared-job co-location.
        assert ac2.via_dataflow is True
        assert "extract" in ac2.reachability_note
        assert "release" in ac2.reachability_note
        assert rendered_path in ac2.narrative
        assert "TAINT-002" in ac2.triggering_check_ids


class TestChainAC003:
    """AC-003 — Unpinned action to credential exfiltration."""

    WF = ".github/workflows/release.yml"

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", ".github/workflows/a.yml"),
            _f("GHA-005", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-003" for c in out)

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # GHA-001 fires in job ``release`` (an unpinned action lives
        # in a step there); GHA-005 anchors on ``release`` too,
        # either because the job sets static keys or because the
        # workflow-level env propagated. Intersection is non-empty;
        # the chain is confirmed reachable with HIGH confidence.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("release",)),
            _f(
                "GHA-005",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac3 = next(c for c in out if c.chain_id == "AC-003")
        assert ac3.confirmed_reachable is True
        assert "release" in ac3.reachability_note
        assert ac3.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # The unpinned action runs in ``build`` while the long-
        # lived AWS keys are confined to a different job. The chain
        # still fires (legacy behavior) but ``confirmed_reachable``
        # is False and confidence stays at the weakest leg.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("build",)),
            _f(
                "GHA-005",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac3 = next(c for c in out if c.chain_id == "AC-003")
        assert ac3.confirmed_reachable is False
        assert ac3.reachability_note == ""
        assert ac3.confidence is Confidence.MEDIUM


class TestChainAC004:
    """AC-004 — Self-Hosted Runner Persistent Foothold."""

    WF = ".github/workflows/ci.yml"

    def test_fires_with_pull_request_target_and_non_ephemeral_runner(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-012", wf)])
        ac4 = [c for c in out if c.chain_id == "AC-004"]
        assert len(ac4) == 1
        assert "T1543" in ac4[0].mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-012", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-004" for c in out)

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("build",)),
            _f(
                "GHA-012",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac4 = next(c for c in out if c.chain_id == "AC-004")
        assert ac4.confirmed_reachable is True
        assert "build" in ac4.reachability_note
        assert ac4.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("label",)),
            _f(
                "GHA-012",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac4 = next(c for c in out if c.chain_id == "AC-004")
        assert ac4.confirmed_reachable is False
        assert ac4.confidence is Confidence.MEDIUM


class TestChainAC006:
    """AC-006 — Cache Poisoning via Untrusted Trigger."""

    WF = ".github/workflows/build.yml"

    def test_fires_with_pull_request_target_and_cache_key_issue(self):
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-011", wf)])
        ac6 = [c for c in out if c.chain_id == "AC-006"]
        assert len(ac6) == 1
        assert ac6[0].severity is Severity.HIGH

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-011", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-006" for c in out)

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # Same job runs PR-head code AND has a poisonable cache key.
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("build",)),
            _f(
                "GHA-011",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac6 = next(c for c in out if c.chain_id == "AC-006")
        assert ac6.confirmed_reachable is True
        assert "build" in ac6.reachability_note
        assert ac6.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # PR-head checkout in ``label``, poisonable cache in ``build``.
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("label",)),
            _f(
                "GHA-011",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac6 = next(c for c in out if c.chain_id == "AC-006")
        assert ac6.confirmed_reachable is False
        assert ac6.reachability_note == ""
        assert ac6.confidence is Confidence.MEDIUM


class TestChainAC008:
    """AC-008 — Dependency Confusion Window."""

    WF = ".github/workflows/release.yml"

    def test_fires_with_no_lockfile_and_integrity_bypass(self):
        out = chains_pkg.evaluate([_f("GHA-021", self.WF), _f("GHA-029", self.WF)])
        ac8 = [c for c in out if c.chain_id == "AC-008"]
        assert len(ac8) == 1
        assert "T1195.001" in ac8[0].mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-021", ".github/workflows/a.yml"),
            _f("GHA-029", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-008" for c in out)

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # Same job both skips the lockfile AND installs from an
        # integrity-bypass source: the tightest dep-confusion window.
        out = chains_pkg.evaluate([
            _f("GHA-021", self.WF, job_anchors=("build",)),
            _f(
                "GHA-029",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac8 = next(c for c in out if c.chain_id == "AC-008")
        assert ac8.confirmed_reachable is True
        assert "build" in ac8.reachability_note
        assert ac8.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # Lockfile miss in ``test``, integrity bypass in ``deploy`` —
        # both still real findings but the chain stays at the
        # weaker co-occurrence signal.
        out = chains_pkg.evaluate([
            _f("GHA-021", self.WF, job_anchors=("test",)),
            _f(
                "GHA-029",
                self.WF,
                job_anchors=("deploy",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac8 = next(c for c in out if c.chain_id == "AC-008")
        assert ac8.confirmed_reachable is False
        assert ac8.reachability_note == ""
        assert ac8.confidence is Confidence.MEDIUM


class TestChainAC007:
    """AC-007 — IAM PrivEsc via CodeBuild (AWS-specific, multi-resource)."""

    PROJECT = "arn:aws:codebuild:.../proj"
    ROLE = "arn:aws:iam::123456789012:role/build"

    def test_fires_with_cb002_plus_iam002(self):
        out = chains_pkg.evaluate([
            _f("CB-002", self.PROJECT),
            _f("IAM-002", self.ROLE),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        assert ac7[0].severity is Severity.CRITICAL

    def test_fires_with_cb002_plus_iam004(self):
        out = chains_pkg.evaluate([
            _f("CB-002", self.PROJECT),
            _f("IAM-004", self.ROLE),
        ])
        assert any(c.chain_id == "AC-007" for c in out)

    def test_does_not_fire_without_iam_leg(self):
        out = chains_pkg.evaluate([_f("CB-002", self.PROJECT)])
        assert not any(c.chain_id == "AC-007" for c in out)

    def test_reachability_confirmed_when_service_role_matches_iam002(self):
        # The privileged CodeBuild project runs AS the wildcard role.
        role_anchor = ResourceAnchor(kind="iam_role", identity=self.ROLE)
        out = chains_pkg.evaluate([
            _f("CB-002", "my-project", resource_anchors=(role_anchor,)),
            _f(
                "IAM-002", "build",
                resource_anchors=(role_anchor,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        chain = ac7[0]
        assert chain.confirmed_reachable is True
        assert self.ROLE in chain.reachability_note
        assert chain.resources == [self.ROLE]
        assert chain.confidence is Confidence.HIGH

    def test_reachability_confirmed_unions_iam002_and_iam004_on_same_role(self):
        # When ONE role triggers BOTH IAM-002 and IAM-004, the chain
        # emits a single confirmed chain carrying both IAM legs (not
        # two separate chains for the same role).
        role_anchor = ResourceAnchor(kind="iam_role", identity=self.ROLE)
        out = chains_pkg.evaluate([
            _f("CB-002", "my-project", resource_anchors=(role_anchor,)),
            _f("IAM-002", "build", resource_anchors=(role_anchor,)),
            _f("IAM-004", "build", resource_anchors=(role_anchor,)),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        chain = ac7[0]
        assert chain.confirmed_reachable is True
        assert set(chain.triggering_check_ids) == {"CB-002", "IAM-002", "IAM-004"}

    def test_falls_back_when_service_role_differs_from_bad_role(self):
        # Privileged project runs as role-A; IAM-002 fires on role-B.
        a = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/role-A",
        )
        b = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/role-B",
        )
        out = chains_pkg.evaluate([
            _f("CB-002", "my-project", resource_anchors=(a,)),
            _f(
                "IAM-002", "role-B",
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        chain = ac7[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM

    def test_confirmed_chain_includes_all_cb002_projects_on_same_role(self):
        # Two CodeBuild projects share the same service role that
        # IAM-002 flagged. One confirmed chain emits, but its
        # triggering_findings must include BOTH CB-002 findings so
        # the blast radius isn't understated.
        role_anchor = ResourceAnchor(kind="iam_role", identity=self.ROLE)
        cb_a = _f(
            "CB-002", "project-a", resource_anchors=(role_anchor,),
        )
        cb_b = _f(
            "CB-002", "project-b", resource_anchors=(role_anchor,),
        )
        iam = _f("IAM-002", "build", resource_anchors=(role_anchor,))
        out = chains_pkg.evaluate([cb_a, cb_b, iam])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        triggers = ac7[0].triggering_findings
        cb_triggers = [t for t in triggers if t.check_id == "CB-002"]
        assert len(cb_triggers) == 2
        assert {t.resource for t in cb_triggers} == {"project-a", "project-b"}


class TestChainAC009:
    """AC-009 — Supply Chain Repo Poisoning."""

    WF = ".github/workflows/release.yml"

    def test_fires_with_all_three_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF),
            _f("GHA-002", self.WF),
            _f("GHA-008", self.WF),
        ])
        ac9 = [c for c in out if c.chain_id == "AC-009"]
        assert len(ac9) == 1
        assert ac9[0].severity is Severity.CRITICAL
        assert "T1195.002" in ac9[0].mitre_attack

    def test_does_not_fire_with_only_two_legs(self):
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF),
            _f("GHA-002", self.WF),
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

    def test_reachability_confirmed_when_all_three_anchor_intersect(self):
        # One job pulls the unpinned action, runs the injection sink,
        # AND has the literal credential in scope — the precise
        # one-execution-context exfil route.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("release",)),
            _f("GHA-002", self.WF, job_anchors=("release",)),
            _f(
                "GHA-008",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac9 = next(c for c in out if c.chain_id == "AC-009")
        assert ac9.confirmed_reachable is True
        assert "release" in ac9.reachability_note
        assert ac9.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_three_jobs_disjoint(self):
        # Unpinned action in ``docs``, injection in ``release``,
        # literal credential at workflow ``env:`` (fans out to all
        # jobs in GHA-008's anchor set, but we pass just ``other``
        # here to simulate a hand-scoped credential block that
        # doesn't reach either release job).
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("docs",)),
            _f("GHA-002", self.WF, job_anchors=("release",)),
            _f(
                "GHA-008",
                self.WF,
                job_anchors=("other",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac9 = next(c for c in out if c.chain_id == "AC-009")
        assert ac9.confirmed_reachable is False
        assert ac9.reachability_note == ""
        assert ac9.confidence is Confidence.MEDIUM


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

    def test_does_not_fire_when_legs_on_different_workflows(self):
        # Self-hosted-runner workflow file is one repo; the curl-pipe
        # leg fires on a separate workflow. The chain narrative is
        # per-file, so neither AC-010 variant should match.
        out = chains_pkg.evaluate([
            _f("GHA-012", ".github/workflows/a.yml"),
            _f("GHA-016", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-010" for c in out)

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

    def test_reachability_confirmed_via_gha019_intersection(self):
        # Same job both runs on a non-ephemeral self-hosted runner
        # AND persists a token to disk — confirmed reachable.
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-012", wf, job_anchors=("build",)),
            _f(
                "GHA-019",
                wf,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac10 = next(c for c in out if c.chain_id == "AC-010")
        assert ac10.confirmed_reachable is True
        assert "build" in ac10.reachability_note
        assert ac10.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_with_only_gha016(self):
        # GHA-016 is a blob scan with no per-job anchors; we don't
        # have enough to confirm reachability from a curl-pipe-only
        # secondary leg.
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([
            _f("GHA-012", wf, job_anchors=("build",)),
            _f("GHA-016", wf, confidence=Confidence.LOW),
        ])
        ac10 = next(c for c in out if c.chain_id == "AC-010")
        assert ac10.confirmed_reachable is False
        assert ac10.confidence is Confidence.LOW


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

    def test_reachability_confirmed_when_pod_sa_matches_binding_subject(self):
        # The hostPath pod runs as the same SA the cluster-admin
        # binding targets — one execution context for node escape +
        # API takeover.
        sa = ResourceAnchor(kind="k8s_sa", identity="prod/build-runner")
        out = chains_pkg.evaluate([
            _f("K8S-013", self.K8S_RESOURCE, resource_anchors=(sa,)),
            _f(
                "K8S-020", self.K8S_RESOURCE,
                resource_anchors=(sa,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac11 = [c for c in out if c.chain_id == "AC-011"]
        assert len(ac11) == 1
        chain = ac11[0]
        assert chain.confirmed_reachable is True
        assert "prod/build-runner" in chain.reachability_note
        assert chain.resources == ["prod/build-runner"]
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_when_pod_sa_differs_from_binding_subject(self):
        # hostPath pod runs as ``prod/app``; cluster-admin binding
        # targets ``ops/admin``. Disjoint anchors → fallback.
        a = ResourceAnchor(kind="k8s_sa", identity="prod/app")
        b = ResourceAnchor(kind="k8s_sa", identity="ops/admin")
        out = chains_pkg.evaluate([
            _f("K8S-013", self.K8S_RESOURCE, resource_anchors=(a,)),
            _f(
                "K8S-020", self.K8S_RESOURCE,
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac11 = [c for c in out if c.chain_id == "AC-011"]
        assert len(ac11) == 1
        chain = ac11[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


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
        # Without job anchors the chain is unconfirmed and confidence
        # falls through to the weakest leg.
        assert ac12.confidence is Confidence.MEDIUM
        assert ac12.confirmed_reachable is False

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # Same call site both unpins the callee AND passes
        # ``secrets: inherit``, the single-step exfil channel.
        out = chains_pkg.evaluate([
            _f("GHA-025", self.WF, job_anchors=("call_release",)),
            _f(
                "GHA-034",
                self.WF,
                job_anchors=("call_release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac12 = next(c for c in out if c.chain_id == "AC-012")
        assert ac12.confirmed_reachable is True
        assert "call_release" in ac12.reachability_note
        assert ac12.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # Unpinned call in ``build``, inherit call in ``deploy`` —
        # two reusable-workflow calls on the same file but neither
        # one exposes both legs, so no single-step exfil.
        out = chains_pkg.evaluate([
            _f("GHA-025", self.WF, job_anchors=("build",)),
            _f(
                "GHA-034",
                self.WF,
                job_anchors=("deploy",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac12 = next(c for c in out if c.chain_id == "AC-012")
        assert ac12.confirmed_reachable is False
        assert ac12.reachability_note == ""
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

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF, job_anchors=("deploy",)),
            _f(
                "GHA-019",
                self.WF,
                job_anchors=("deploy",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac13 = next(c for c in out if c.chain_id == "AC-013")
        assert ac13.confirmed_reachable is True
        assert "deploy" in ac13.reachability_note
        assert ac13.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF, job_anchors=("build",)),
            _f(
                "GHA-019",
                self.WF,
                job_anchors=("deploy",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac13 = next(c for c in out if c.chain_id == "AC-013")
        assert ac13.confirmed_reachable is False
        assert ac13.confidence is Confidence.MEDIUM


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

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        out = chains_pkg.evaluate([
            _f("GL-032", self.PIPELINE, job_anchors=("release",)),
            _f(
                "GL-020",
                self.PIPELINE,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac14 = next(c for c in out if c.chain_id == "AC-014")
        assert ac14.confirmed_reachable is True
        assert "release" in ac14.reachability_note
        assert ac14.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        out = chains_pkg.evaluate([
            _f("GL-032", self.PIPELINE, job_anchors=("build",)),
            _f(
                "GL-020",
                self.PIPELINE,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac14 = next(c for c in out if c.chain_id == "AC-014")
        assert ac14.confirmed_reachable is False
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

    def test_reachability_confirmed_when_role_anchor_matches(self):
        # ResourceAnchor phase 1 pilot: the workflow's
        # ``role-to-assume`` resolves to the same ARN IAM-002 flagged
        # for wildcard authority. Confirmed chain cites the role ARN
        # as the resource and promotes confidence.
        role_anchor = ResourceAnchor(kind="iam_role", identity=self.ROLE)
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF, resource_anchors=(role_anchor,)),
            _f(
                "IAM-002",
                "ci-deploy",
                resource_anchors=(role_anchor,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac16 = [c for c in out if c.chain_id == "AC-016"]
        assert len(ac16) == 1
        chain = ac16[0]
        assert chain.confirmed_reachable is True
        assert self.ROLE in chain.reachability_note
        assert chain.resources == [self.ROLE]
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_to_cooccurrence_when_anchors_disjoint(self):
        # GHA-030 names ``role-A``; IAM-002 fires on ``role-B``.
        # No role-anchor intersection, so the chain falls back to
        # the scan-level co-occurrence signal at min-confidence.
        a = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/ci-A",
        )
        b = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/ci-B",
        )
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF, resource_anchors=(a,)),
            _f(
                "IAM-002",
                "ci-B",
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac16 = [c for c in out if c.chain_id == "AC-016"]
        assert len(ac16) == 1
        chain = ac16[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM

    def test_one_confirmed_chain_per_matched_role(self):
        # Two workflows each name a different wildcard role; IAM-002
        # fires on both. Expect two confirmed chains, one per role.
        role_a = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/ci-A",
        )
        role_b = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/ci-B",
        )
        out = chains_pkg.evaluate([
            _f(
                "GHA-030", ".github/workflows/a.yml",
                resource_anchors=(role_a,),
            ),
            _f(
                "GHA-030", ".github/workflows/b.yml",
                resource_anchors=(role_b,),
            ),
            _f("IAM-002", "ci-A", resource_anchors=(role_a,)),
            _f("IAM-002", "ci-B", resource_anchors=(role_b,)),
        ])
        ac16 = [c for c in out if c.chain_id == "AC-016"]
        assert len(ac16) == 2
        confirmed = [c for c in ac16 if c.confirmed_reachable]
        assert len(confirmed) == 2
        assert {c.resources[0] for c in confirmed} == {
            role_a.identity, role_b.identity,
        }

    def test_fallback_fans_out_one_chain_per_unmatched_pair(self):
        # Two GHA-030 workflows and three IAM-002 roles, none of which
        # share role-ARN anchors → six fallback chains (one per pair),
        # not one composite merging unrelated legs. Each chain's
        # triggering_findings names exactly the (workflow, role) pair
        # that composed it.
        out = chains_pkg.evaluate([
            _f("GHA-030", ".github/workflows/a.yml"),
            _f("GHA-030", ".github/workflows/b.yml"),
            _f("IAM-002", "role-1"),
            _f("IAM-002", "role-2"),
            _f("IAM-002", "role-3"),
        ])
        ac16 = [c for c in out if c.chain_id == "AC-016"]
        # 2 workflows × 3 roles = 6 unmatched-pair chains.
        assert len(ac16) == 6
        assert all(not c.confirmed_reachable for c in ac16)
        # Each chain carries exactly two triggering findings (its pair).
        assert all(len(c.triggering_findings) == 2 for c in ac16)
        # Every (workflow, role) cell is covered exactly once.
        pairs = {tuple(sorted(c.resources)) for c in ac16}
        assert len(pairs) == 6


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

    def test_reachability_confirmed_when_repo_uri_matches(self):
        # The workflow text references the same ECR repo URI that
        # ECR-002 flagged as mutable. Tight reachability claim.
        uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp"
        repo_anchor = ResourceAnchor(kind="ecr_repo", identity=uri)
        out = chains_pkg.evaluate([
            _f("GHA-011", self.WF, resource_anchors=(repo_anchor,)),
            _f(
                "ECR-002", self.REPO,
                resource_anchors=(repo_anchor,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac17 = [c for c in out if c.chain_id == "AC-017"]
        assert len(ac17) == 1
        chain = ac17[0]
        assert chain.confirmed_reachable is True
        assert uri in chain.reachability_note
        assert chain.resources == [uri]
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_to_cooccurrence_when_repos_disjoint(self):
        # Workflow pushes to repo-A; ECR-002 flagged repo-B as
        # mutable. Co-occurrence fallback preserves the legacy
        # "cache poisoning + mutable tag somewhere" signal.
        a = ResourceAnchor(
            kind="ecr_repo",
            identity="123456789012.dkr.ecr.us-east-1.amazonaws.com/repo-A",
        )
        b = ResourceAnchor(
            kind="ecr_repo",
            identity="123456789012.dkr.ecr.us-east-1.amazonaws.com/repo-B",
        )
        out = chains_pkg.evaluate([
            _f("GHA-011", self.WF, resource_anchors=(a,)),
            _f(
                "ECR-002", "repo-B",
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac17 = [c for c in out if c.chain_id == "AC-017"]
        assert len(ac17) == 1
        chain = ac17[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
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

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # GHA-001 fires in job ``release`` (an unpinned action lives
        # in a step there), GHA-014 reports ``release`` as an
        # ungated deploy. Intersection is non-empty so the chain is
        # confirmed reachable; composite confidence promoted to HIGH
        # even when GHA-014 is MEDIUM on its own.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("release",)),
            _f(
                "GHA-014",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac18 = next(c for c in out if c.chain_id == "AC-018")
        assert ac18.confirmed_reachable is True
        assert "release" in ac18.reachability_note
        assert ac18.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # Unpinned action in ``build``, ungated deploy in ``release``,
        # no dataflow link recorded. Chain still fires (legacy
        # behavior) but confirmed_reachable is False and confidence
        # stays at the weakest leg.
        out = chains_pkg.evaluate([
            _f("GHA-001", self.WF, job_anchors=("build",)),
            _f(
                "GHA-014",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac18 = next(c for c in out if c.chain_id == "AC-018")
        assert ac18.confirmed_reachable is False
        assert ac18.reachability_note == ""
        assert ac18.confidence is Confidence.MEDIUM


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

    def test_same_role_emits_role_specific_narrative_but_stays_unconfirmed(self):
        # The LMB-003 Lambda's execution role IS the IAM-004
        # wildcard-PassRole role. Same-role tightening produces a
        # per-role chain whose narrative cites the role-equality,
        # but ``confirmed_reachable`` stays False and confidence
        # stays at min_leg: LMB-003 only proves a credential-shaped
        # literal is in the env vars, not that the leaked value is
        # an AWS credential for THIS role.
        role_anchor = ResourceAnchor(kind="iam_role", identity=self.ROLE)
        fn_anchor = ResourceAnchor(kind="lambda_fn", identity=self.LAMBDA)
        out = chains_pkg.evaluate([
            _f(
                "LMB-003", "my-fn",
                resource_anchors=(fn_anchor, role_anchor),
            ),
            _f(
                "IAM-004", "ci-deploy",
                resource_anchors=(role_anchor,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac19 = [c for c in out if c.chain_id == "AC-019"]
        assert len(ac19) == 1
        chain = ac19[0]
        assert chain.confirmed_reachable is False
        assert self.ROLE in chain.reachability_note
        assert "role-equality only" in chain.reachability_note
        assert chain.resources == [self.ROLE]
        # Weakest-leg confidence propagates; HIGH would overclaim.
        assert chain.confidence is Confidence.MEDIUM

    def test_falls_back_when_execution_role_differs_from_passrole(self):
        # The Lambda runs as ``role-A``; the PassRole-* role is
        # ``role-B``. Co-occurrence fallback at min confidence.
        a = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/role-A",
        )
        b = ResourceAnchor(
            kind="iam_role",
            identity="arn:aws:iam::123456789012:role/role-B",
        )
        fn = ResourceAnchor(kind="lambda_fn", identity=self.LAMBDA)
        out = chains_pkg.evaluate([
            _f("LMB-003", "my-fn", resource_anchors=(fn, a)),
            _f(
                "IAM-004", "ci-deploy",
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac19 = [c for c in out if c.chain_id == "AC-019"]
        assert len(ac19) == 1
        chain = ac19[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC020:
    """AC-020 — Tekton hostPath build workload meets cluster-admin RBAC."""

    TASK = "tekton/build-task.yaml"
    BINDING = "kubernetes/manifests"

    def test_fires_when_both_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK),
            _f("K8S-020", self.BINDING),
        ])
        ac20 = [c for c in out if c.chain_id == "AC-020"]
        assert len(ac20) == 1
        assert ac20[0].severity is Severity.CRITICAL
        assert "T1611" in ac20[0].mitre_attack
        assert "T1098.003" in ac20[0].mitre_attack

    def test_does_not_fire_without_tkn004(self):
        out = chains_pkg.evaluate([_f("K8S-020", self.BINDING)])
        assert not any(c.chain_id == "AC-020" for c in out)

    def test_does_not_fire_without_k8s020(self):
        out = chains_pkg.evaluate([_f("TKN-004", self.TASK)])
        assert not any(c.chain_id == "AC-020" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK, passed=True),
            _f("K8S-020", self.BINDING, passed=True),
        ])
        assert not any(c.chain_id == "AC-020" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK),
            _f("K8S-020", self.BINDING),
        ])
        chain = next(c for c in out if c.chain_id == "AC-020")
        assert "initial-access" in chain.kill_chain_phase
        assert "lateral-movement" in chain.kill_chain_phase

    def test_resources_dedupe_across_files(self):
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK),
            _f("K8S-020", self.BINDING),
        ])
        chain = next(c for c in out if c.chain_id == "AC-020")
        assert set(chain.resources) == {self.TASK, self.BINDING}
        assert len(chain.resources) == len(set(chain.resources))

    def test_reachability_confirmed_when_task_sa_matches_binding_subject(self):
        # Task pins podTemplate.serviceAccountName to the same SA the
        # cluster-admin binding targets.
        sa = ResourceAnchor(kind="k8s_sa", identity="build/build-runner")
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK, resource_anchors=(sa,)),
            _f(
                "K8S-020", self.BINDING,
                resource_anchors=(sa,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac20 = [c for c in out if c.chain_id == "AC-020"]
        assert len(ac20) == 1
        chain = ac20[0]
        assert chain.confirmed_reachable is True
        assert "build/build-runner" in chain.reachability_note
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_when_task_has_no_pinned_sa(self):
        # TKN-004 emits no anchors when the Task doesn't pin its SA
        # (the common case). Co-occurrence fallback applies.
        out = chains_pkg.evaluate([
            _f("TKN-004", self.TASK),  # no resource_anchors
            _f(
                "K8S-020", self.BINDING,
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac20 = [c for c in out if c.chain_id == "AC-020"]
        assert len(ac20) == 1
        chain = ac20[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC021:
    """AC-021 — Argo default-SA workflow lands on a default-SA RoleBinding."""

    WF = "argo/build-workflow.yaml"
    BINDING = "kubernetes/manifests"

    def test_fires_when_both_legs_fail(self):
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF),
            _f("K8S-029", self.BINDING),
        ])
        ac21 = [c for c in out if c.chain_id == "AC-021"]
        assert len(ac21) == 1
        assert ac21[0].severity is Severity.HIGH
        assert "T1078" in ac21[0].mitre_attack
        assert "T1098.003" in ac21[0].mitre_attack

    def test_does_not_fire_without_argo003(self):
        out = chains_pkg.evaluate([_f("K8S-029", self.BINDING)])
        assert not any(c.chain_id == "AC-021" for c in out)

    def test_does_not_fire_without_k8s029(self):
        out = chains_pkg.evaluate([_f("ARGO-003", self.WF)])
        assert not any(c.chain_id == "AC-021" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF, passed=True),
            _f("K8S-029", self.BINDING, passed=True),
        ])
        assert not any(c.chain_id == "AC-021" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF),
            _f("K8S-029", self.BINDING),
        ])
        chain = next(c for c in out if c.chain_id == "AC-021")
        assert "initial-access" in chain.kill_chain_phase
        assert "privilege-escalation" in chain.kill_chain_phase

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF, confidence=Confidence.HIGH),
            _f("K8S-029", self.BINDING, confidence=Confidence.LOW),
        ])
        chain = next(c for c in out if c.chain_id == "AC-021")
        assert chain.confidence is Confidence.LOW

    def test_reachability_confirmed_when_workflow_ns_matches_binding_ns(self):
        # Workflow runs as ``prod/default`` and the binding grants to
        # ``prod/default`` — single-namespace single-step privesc.
        sa = ResourceAnchor(kind="k8s_sa", identity="prod/default")
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF, resource_anchors=(sa,)),
            _f(
                "K8S-029", self.BINDING,
                resource_anchors=(sa,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac21 = [c for c in out if c.chain_id == "AC-021"]
        assert len(ac21) == 1
        chain = ac21[0]
        assert chain.confirmed_reachable is True
        assert "prod/default" in chain.reachability_note
        assert chain.confidence is Confidence.HIGH

    def test_falls_back_when_workflow_and_binding_in_different_namespaces(self):
        # ARGO-003 in ``prod``, K8S-029 in ``ops`` — chain remains a
        # hygiene prompt at the lower confidence.
        a = ResourceAnchor(kind="k8s_sa", identity="prod/default")
        b = ResourceAnchor(kind="k8s_sa", identity="ops/default")
        out = chains_pkg.evaluate([
            _f("ARGO-003", self.WF, resource_anchors=(a,)),
            _f(
                "K8S-029", self.BINDING,
                resource_anchors=(b,),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac21 = [c for c in out if c.chain_id == "AC-021"]
        assert len(ac21) == 1
        chain = ac21[0]
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC022:
    """AC-022 — GitLab script injection meets unguarded deploy."""

    WF = ".gitlab-ci.yml"
    OTHER_WF = "ci/sub-pipeline.yml"

    def test_fires_when_both_legs_on_same_file(self):
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF),
            _f("GL-004", self.WF),
        ])
        ac22 = [c for c in out if c.chain_id == "AC-022"]
        assert len(ac22) == 1
        assert ac22[0].severity is Severity.CRITICAL
        assert set(ac22[0].triggering_check_ids) == {"GL-002", "GL-004"}
        assert "T1059" in ac22[0].mitre_attack
        assert "T1078" in ac22[0].mitre_attack
        assert "T1556" in ac22[0].mitre_attack

    def test_does_not_fire_on_different_files(self):
        # The chain narrative is per-file: an injection in one
        # pipeline file co-existing with a missing gate in a
        # different pipeline file isn't the same end-to-end path.
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF),
            _f("GL-004", self.OTHER_WF),
        ])
        assert not any(c.chain_id == "AC-022" for c in out)

    def test_does_not_fire_without_gl002(self):
        out = chains_pkg.evaluate([_f("GL-004", self.WF)])
        assert not any(c.chain_id == "AC-022" for c in out)

    def test_does_not_fire_without_gl004(self):
        out = chains_pkg.evaluate([_f("GL-002", self.WF)])
        assert not any(c.chain_id == "AC-022" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, passed=True),
            _f("GL-004", self.WF, passed=True),
        ])
        assert not any(c.chain_id == "AC-022" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF), _f("GL-004", self.WF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-022")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase
        assert "impact" in chain.kill_chain_phase

    def test_resources_dedupe_per_file(self):
        # group_by_resource produces one Chain per file. With one
        # file, exactly one chain instance, with that one resource.
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF),
            _f("GL-004", self.WF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-022")
        assert chain.resources == [self.WF]
        assert len(chain.resources) == len(set(chain.resources))

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, confidence=Confidence.HIGH),
            _f("GL-004", self.WF, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-022")
        assert chain.confidence is Confidence.MEDIUM

    def test_fires_per_file_when_two_files_each_have_both_legs(self):
        # Two .gitlab-ci.yml files (monorepo with multiple pipelines)
        # each independently triggers — each is a separate chain.
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF),
            _f("GL-004", self.WF),
            _f("GL-002", self.OTHER_WF),
            _f("GL-004", self.OTHER_WF),
        ])
        ac22 = [c for c in out if c.chain_id == "AC-022"]
        assert len(ac22) == 2
        assert {c.resources[0] for c in ac22} == {self.WF, self.OTHER_WF}

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # GL-002 fires in job ``release``, GL-004 reports ``release``
        # as an ungated deploy job. The intersection is non-empty so
        # the chain is confirmed reachable, composite confidence
        # promoted to HIGH even when a leg is MEDIUM on its own.
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, job_anchors=("release",)),
            _f(
                "GL-004",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac22 = next(c for c in out if c.chain_id == "AC-022")
        assert ac22.confirmed_reachable is True
        assert "release" in ac22.reachability_note
        assert ac22.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # Two legs fire on the same file but in distinct jobs and no
        # dataflow rule corroborates a cross-job hop. The chain still
        # fires (legacy behavior) but ``confirmed_reachable`` is False
        # and the confidence stays at the weakest leg.
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, job_anchors=("triage",)),
            _f(
                "GL-004",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac22 = next(c for c in out if c.chain_id == "AC-022")
        assert ac22.confirmed_reachable is False
        assert ac22.reachability_note == ""
        assert ac22.confidence is Confidence.MEDIUM

    def test_taint004_widens_injection_side_for_reachability(self):
        # GL-002 fires only in ``extract``, but TAINT-004 reports a
        # dotenv-routed taint whose sink lands in ``release`` — the
        # same job GL-004 names as ungated. The chain is reachable
        # via the dotenv hop even though GL-002 alone wouldn't
        # intersect.
        rendered_path = (
            "$CI_COMMIT_TITLE@extract:script[0] -> "
            "jobs.extract.artifacts.reports.dotenv -> $TITLE -> "
            "sink@release:script[2]($TITLE)"
        )
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, job_anchors=("extract",)),
            _f(
                "TAINT-004",
                self.WF,
                job_anchors=("release",),
                path_evidence=(rendered_path,),
                taint_flows=(
                    TaintFlow(
                        source_job="extract",
                        sink_job="release",
                        rendered=rendered_path,
                    ),
                ),
            ),
            _f("GL-004", self.WF, job_anchors=("release",)),
        ])
        ac22 = next(c for c in out if c.chain_id == "AC-022")
        assert ac22.confirmed_reachable is True
        assert ac22.via_dataflow is True
        assert "release" in ac22.reachability_note
        assert rendered_path in ac22.narrative
        assert "TAINT-004" in ac22.triggering_check_ids

    def test_taint008_widens_injection_side_for_reachability(self):
        # GL-002 fires only in a hidden producer template, but
        # TAINT-008 reports an ``extends:`` inheritance taint whose
        # sink lands in ``release`` — the same job GL-004 names as
        # ungated. The chain is reachable via the extends-chain hop
        # even though GL-002 anchored elsewhere.
        rendered_path = (
            "$CI_COMMIT_TITLE@.base.variables.TITLE -> "
            "extends.<chain> -> $TITLE -> "
            "sink@release:script[1]($TITLE)"
        )
        out = chains_pkg.evaluate([
            _f("GL-002", self.WF, job_anchors=("seed",)),
            _f(
                "TAINT-008",
                self.WF,
                job_anchors=("release",),
                path_evidence=(rendered_path,),
                taint_flows=(
                    # extends inheritance is a self-edge: the tainted
                    # template var is inherited into and consumed by the
                    # same (release) job.
                    TaintFlow(
                        source_job="release",
                        sink_job="release",
                        rendered=rendered_path,
                    ),
                ),
            ),
            _f("GL-004", self.WF, job_anchors=("release",)),
        ])
        ac22 = next(c for c in out if c.chain_id == "AC-022")
        assert ac22.confirmed_reachable is True
        assert ac22.via_dataflow is True
        assert "release" in ac22.reachability_note
        assert rendered_path in ac22.narrative
        assert "TAINT-008" in ac22.triggering_check_ids


class TestChainAC023:
    """AC-023 — Tekton param injection lands in a privileged step."""

    TASK = "tekton/build-task.yaml"
    OTHER_TASK = "tekton/release-task.yaml"

    def test_fires_when_both_legs_on_same_task(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK),
            _f("TKN-003", self.TASK),
        ])
        ac23 = [c for c in out if c.chain_id == "AC-023"]
        assert len(ac23) == 1
        assert ac23[0].severity is Severity.CRITICAL
        assert set(ac23[0].triggering_check_ids) == {"TKN-002", "TKN-003"}
        assert "T1059" in ac23[0].mitre_attack
        assert "T1068" in ac23[0].mitre_attack
        assert "T1611" in ac23[0].mitre_attack

    def test_does_not_fire_on_different_tasks(self):
        # Privileged step on Task A and param injection on Task B
        # don't compose — the chain claim is *same Task*, which is
        # what determines whether the injected command actually
        # lands in the privileged container.
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK),
            _f("TKN-003", self.OTHER_TASK),
        ])
        assert not any(c.chain_id == "AC-023" for c in out)

    def test_does_not_fire_without_tkn002(self):
        out = chains_pkg.evaluate([_f("TKN-003", self.TASK)])
        assert not any(c.chain_id == "AC-023" for c in out)

    def test_does_not_fire_without_tkn003(self):
        out = chains_pkg.evaluate([_f("TKN-002", self.TASK)])
        assert not any(c.chain_id == "AC-023" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK, passed=True),
            _f("TKN-003", self.TASK, passed=True),
        ])
        assert not any(c.chain_id == "AC-023" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK), _f("TKN-003", self.TASK),
        ])
        chain = next(c for c in out if c.chain_id == "AC-023")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase
        assert "privilege-escalation" in chain.kill_chain_phase

    def test_resources_dedupe_per_task(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK),
            _f("TKN-003", self.TASK),
        ])
        chain = next(c for c in out if c.chain_id == "AC-023")
        assert chain.resources == [self.TASK]
        assert len(chain.resources) == len(set(chain.resources))

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK, confidence=Confidence.HIGH),
            _f("TKN-003", self.TASK, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-023")
        assert chain.confidence is Confidence.MEDIUM

    def test_fires_per_task_when_multiple_tasks_each_have_both(self):
        out = chains_pkg.evaluate([
            _f("TKN-002", self.TASK),
            _f("TKN-003", self.TASK),
            _f("TKN-002", self.OTHER_TASK),
            _f("TKN-003", self.OTHER_TASK),
        ])
        ac23 = [c for c in out if c.chain_id == "AC-023"]
        assert len(ac23) == 2
        assert {c.resources[0] for c in ac23} == {self.TASK, self.OTHER_TASK}

    def test_reachability_confirmed_when_step_anchors_intersect(self):
        # The same step (``Task/build:build-image``) both runs
        # privileged AND interpolates an unsafe param — the precise
        # node-escape primitive.
        out = chains_pkg.evaluate([
            _f(
                "TKN-002",
                self.TASK,
                job_anchors=("Task/build:build-image",),
            ),
            _f(
                "TKN-003",
                self.TASK,
                job_anchors=("Task/build:build-image",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        chain = next(c for c in out if c.chain_id == "AC-023")
        assert chain.confirmed_reachable is True
        assert "Task/build:build-image" in chain.reachability_note
        assert chain.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_steps_disjoint(self):
        # Privileged step is ``build``, param-injection sink is
        # ``release``. Both Tasks fire but neither single step
        # exposes the kernel-RCE shape, fall back to the
        # co-occurrence signal.
        out = chains_pkg.evaluate([
            _f(
                "TKN-002",
                self.TASK,
                job_anchors=("Task/build:build",),
            ),
            _f(
                "TKN-003",
                self.TASK,
                job_anchors=("Task/build:release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        chain = next(c for c in out if c.chain_id == "AC-023")
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC024:
    """AC-024 — OIDC trust drift lands on a mutable ECR tag."""

    WF = ".github/workflows/release.yml"
    REPO = "arn:aws:ecr:us-east-1:123456789012:repository/myapp"
    OTHER_REPO = "arn:aws:ecr:us-east-1:123456789012:repository/other"

    def test_fires_when_both_legs_present(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("ECR-002", self.REPO),
        ])
        ac24 = [c for c in out if c.chain_id == "AC-024"]
        assert len(ac24) == 1
        assert ac24[0].severity is Severity.CRITICAL
        assert set(ac24[0].triggering_check_ids) == {"GHA-030", "ECR-002"}
        assert "T1078.004" in ac24[0].mitre_attack
        assert "T1195.002" in ac24[0].mitre_attack
        assert "T1525" in ac24[0].mitre_attack

    def test_does_not_fire_without_gha030(self):
        out = chains_pkg.evaluate([_f("ECR-002", self.REPO)])
        assert not any(c.chain_id == "AC-024" for c in out)

    def test_does_not_fire_without_ecr002(self):
        out = chains_pkg.evaluate([_f("GHA-030", self.WF)])
        assert not any(c.chain_id == "AC-024" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF, passed=True),
            _f("ECR-002", self.REPO, passed=True),
        ])
        assert not any(c.chain_id == "AC-024" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("ECR-002", self.REPO),
        ])
        chain = next(c for c in out if c.chain_id == "AC-024")
        assert "initial-access" in chain.kill_chain_phase
        assert "credential-access" in chain.kill_chain_phase
        assert "impact" in chain.kill_chain_phase

    def test_resources_collect_both_legs_dedup(self):
        # Cross-resource chain: a single workflow + multiple ECR
        # repos with mutable tags all surface in the chain's
        # resources list, deduped.
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("ECR-002", self.REPO),
            _f("ECR-002", self.OTHER_REPO),
        ])
        chain = next(c for c in out if c.chain_id == "AC-024")
        assert set(chain.resources) == {self.WF, self.REPO, self.OTHER_REPO}
        assert len(chain.resources) == len(set(chain.resources))

    def test_fires_once_even_with_multiple_workflows_and_repos(self):
        # has_failing-style chain: one chain instance per scan, not
        # per (workflow, repo) cross product. Attribution between a
        # specific workflow and a specific repo lives across two
        # planes — the chain claim is only that *some* OIDC-drifty
        # workflow exists alongside *some* mutable-tag repo.
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF),
            _f("GHA-030", ".github/workflows/deploy.yml"),
            _f("ECR-002", self.REPO),
            _f("ECR-002", self.OTHER_REPO),
        ])
        ac24 = [c for c in out if c.chain_id == "AC-024"]
        assert len(ac24) == 1

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("GHA-030", self.WF, confidence=Confidence.HIGH),
            _f("ECR-002", self.REPO, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-024")
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC025:
    """AC-025 — Argo param injection lands in a privileged step."""

    WF = "argo/build-workflow.yaml"
    OTHER_WF = "argo/release-workflow.yaml"

    def test_fires_when_both_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF),
            _f("ARGO-005", self.WF),
        ])
        ac25 = [c for c in out if c.chain_id == "AC-025"]
        assert len(ac25) == 1
        assert ac25[0].severity is Severity.CRITICAL
        assert set(ac25[0].triggering_check_ids) == {"ARGO-002", "ARGO-005"}
        assert "T1059" in ac25[0].mitre_attack
        assert "T1068" in ac25[0].mitre_attack
        assert "T1611" in ac25[0].mitre_attack

    def test_does_not_fire_on_different_workflows(self):
        # Privilege on one Workflow + param injection on another
        # don't compose — same-template co-occurrence is the
        # claim. Different templates means the injected command
        # doesn't land in the privileged container.
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF),
            _f("ARGO-005", self.OTHER_WF),
        ])
        assert not any(c.chain_id == "AC-025" for c in out)

    def test_does_not_fire_without_argo002(self):
        out = chains_pkg.evaluate([_f("ARGO-005", self.WF)])
        assert not any(c.chain_id == "AC-025" for c in out)

    def test_does_not_fire_without_argo005(self):
        out = chains_pkg.evaluate([_f("ARGO-002", self.WF)])
        assert not any(c.chain_id == "AC-025" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF, passed=True),
            _f("ARGO-005", self.WF, passed=True),
        ])
        assert not any(c.chain_id == "AC-025" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF), _f("ARGO-005", self.WF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-025")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase
        assert "privilege-escalation" in chain.kill_chain_phase

    def test_resources_dedupe_per_workflow(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF),
            _f("ARGO-005", self.WF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-025")
        assert chain.resources == [self.WF]
        assert len(chain.resources) == len(set(chain.resources))

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF, confidence=Confidence.HIGH),
            _f("ARGO-005", self.WF, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-025")
        assert chain.confidence is Confidence.MEDIUM

    def test_fires_per_workflow_when_multiple_have_both(self):
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF),
            _f("ARGO-005", self.WF),
            _f("ARGO-002", self.OTHER_WF),
            _f("ARGO-005", self.OTHER_WF),
        ])
        ac25 = [c for c in out if c.chain_id == "AC-025"]
        assert len(ac25) == 2
        assert {c.resources[0] for c in ac25} == {self.WF, self.OTHER_WF}

    def test_orthogonal_to_ac021(self):
        # AC-021 (ARGO-003 + K8S-029) and AC-025 (ARGO-002 + ARGO-005)
        # capture genuinely different attack stages on the Argo
        # surface. A scan that triggers AC-025 should NOT also
        # trigger AC-021 unless the AC-021 legs are independently
        # present — they share zero check_ids.
        out = chains_pkg.evaluate([
            _f("ARGO-002", self.WF),
            _f("ARGO-005", self.WF),
        ])
        chain_ids = {c.chain_id for c in out}
        assert "AC-025" in chain_ids
        assert "AC-021" not in chain_ids

    def test_reachability_confirmed_when_template_anchors_intersect(self):
        # The same template (``Workflow/build:main``) both runs
        # privileged AND interpolates an unsafe param — the precise
        # node-escape primitive.
        out = chains_pkg.evaluate([
            _f(
                "ARGO-002",
                self.WF,
                job_anchors=("Workflow/build:main",),
            ),
            _f(
                "ARGO-005",
                self.WF,
                job_anchors=("Workflow/build:main",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        chain = next(c for c in out if c.chain_id == "AC-025")
        assert chain.confirmed_reachable is True
        assert "Workflow/build:main" in chain.reachability_note
        assert chain.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_templates_disjoint(self):
        # Privileged template is ``init``, param-injection sink is
        # ``deploy``. Both findings fire on the same workflow file
        # but neither single template exposes the kernel-RCE shape.
        out = chains_pkg.evaluate([
            _f(
                "ARGO-002",
                self.WF,
                job_anchors=("Workflow/build:init",),
            ),
            _f(
                "ARGO-005",
                self.WF,
                job_anchors=("Workflow/build:deploy",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        chain = next(c for c in out if c.chain_id == "AC-025")
        assert chain.confirmed_reachable is False
        assert chain.reachability_note == ""
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC026:
    """AC-026 — Buildkite injection lands on auto-deploy step."""

    PIPELINE = ".buildkite/pipeline.yml"
    OTHER_PIPELINE = ".buildkite/release.yml"

    def test_fires_when_both_legs_on_same_pipeline(self):
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE),
            _f("BK-007", self.PIPELINE),
        ])
        ac26 = [c for c in out if c.chain_id == "AC-026"]
        assert len(ac26) == 1
        assert ac26[0].severity is Severity.CRITICAL
        assert set(ac26[0].triggering_check_ids) == {"BK-003", "BK-007"}
        assert "T1059" in ac26[0].mitre_attack
        assert "T1078" in ac26[0].mitre_attack
        assert "T1556" in ac26[0].mitre_attack

    def test_does_not_fire_on_different_pipelines(self):
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE),
            _f("BK-007", self.OTHER_PIPELINE),
        ])
        assert not any(c.chain_id == "AC-026" for c in out)

    def test_does_not_fire_without_bk003(self):
        out = chains_pkg.evaluate([_f("BK-007", self.PIPELINE)])
        assert not any(c.chain_id == "AC-026" for c in out)

    def test_does_not_fire_without_bk007(self):
        out = chains_pkg.evaluate([_f("BK-003", self.PIPELINE)])
        assert not any(c.chain_id == "AC-026" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE, passed=True),
            _f("BK-007", self.PIPELINE, passed=True),
        ])
        assert not any(c.chain_id == "AC-026" for c in out)

    def test_kill_chain_phase_matches_ac002_ac022_shape(self):
        # AC-026 is the Buildkite peer of AC-002 (GHA) and AC-022
        # (GitLab). The kill chain phase must read the same way:
        # initial-access -> execution -> impact.
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE), _f("BK-007", self.PIPELINE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-026")
        assert "initial-access" in chain.kill_chain_phase
        assert "execution" in chain.kill_chain_phase
        assert "impact" in chain.kill_chain_phase

    def test_confidence_picks_lowest_leg(self):
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE, confidence=Confidence.HIGH),
            _f("BK-007", self.PIPELINE, confidence=Confidence.LOW),
        ])
        chain = next(c for c in out if c.chain_id == "AC-026")
        assert chain.confidence is Confidence.LOW

    def test_reachability_confirmed_when_step_anchors_intersect(self):
        # BK-003 fires on step ``release``, BK-007 names ``release``
        # as the ungated deploy. Same step is both the injection
        # sink AND the unmanual deploy — the strongest signal.
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE, job_anchors=("release",)),
            _f(
                "BK-007",
                self.PIPELINE,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac26 = next(c for c in out if c.chain_id == "AC-026")
        assert ac26.confirmed_reachable is True
        assert "release" in ac26.reachability_note
        assert ac26.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_steps_disjoint(self):
        # Two legs fire on the same pipeline but on distinct steps,
        # no cross-step dataflow rule corroborates. The chain still
        # fires (legacy behavior) but ``confirmed_reachable`` is
        # False and confidence stays at the weakest leg.
        out = chains_pkg.evaluate([
            _f("BK-003", self.PIPELINE, job_anchors=("build",)),
            _f(
                "BK-007",
                self.PIPELINE,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac26 = next(c for c in out if c.chain_id == "AC-026")
        assert ac26.confirmed_reachable is False
        assert ac26.reachability_note == ""
        assert ac26.confidence is Confidence.MEDIUM


class TestChainAC027:
    """AC-027 — Dockerfile credential file + exposed remote-access port."""

    DF = "Dockerfile"
    OTHER_DF = "build/Dockerfile.test"

    def test_fires_when_both_legs_on_same_dockerfile(self):
        out = chains_pkg.evaluate([
            _f("DF-013", self.DF),
            _f("DF-019", self.DF),
        ])
        ac27 = [c for c in out if c.chain_id == "AC-027"]
        assert len(ac27) == 1
        assert ac27[0].severity is Severity.CRITICAL
        assert set(ac27[0].triggering_check_ids) == {"DF-013", "DF-019"}
        # The kill chain shape — credential-access + initial-access +
        # lateral-movement — is what makes AC-027 distinct from the
        # injection-shaped chains. Lock it in.
        assert "T1552.001" in ac27[0].mitre_attack
        assert "T1078" in ac27[0].mitre_attack

    def test_does_not_fire_on_different_dockerfiles(self):
        # An ssh key in image A and an ``EXPOSE 22`` in image B don't
        # compose — the credential-and-listener pair must ship in the
        # same image.
        out = chains_pkg.evaluate([
            _f("DF-013", self.DF),
            _f("DF-019", self.OTHER_DF),
        ])
        assert not any(c.chain_id == "AC-027" for c in out)

    def test_does_not_fire_without_df013(self):
        out = chains_pkg.evaluate([_f("DF-019", self.DF)])
        assert not any(c.chain_id == "AC-027" for c in out)

    def test_does_not_fire_without_df019(self):
        out = chains_pkg.evaluate([_f("DF-013", self.DF)])
        assert not any(c.chain_id == "AC-027" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("DF-013", self.DF, passed=True),
            _f("DF-019", self.DF, passed=True),
        ])
        assert not any(c.chain_id == "AC-027" for c in out)

    def test_kill_chain_phase_set(self):
        out = chains_pkg.evaluate([
            _f("DF-013", self.DF), _f("DF-019", self.DF),
        ])
        chain = next(c for c in out if c.chain_id == "AC-027")
        assert "credential-access" in chain.kill_chain_phase
        assert "initial-access" in chain.kill_chain_phase
        assert "lateral-movement" in chain.kill_chain_phase

    def test_fires_per_dockerfile_when_multiple_have_both(self):
        out = chains_pkg.evaluate([
            _f("DF-013", self.DF),
            _f("DF-019", self.DF),
            _f("DF-013", self.OTHER_DF),
            _f("DF-019", self.OTHER_DF),
        ])
        ac27 = [c for c in out if c.chain_id == "AC-027"]
        assert len(ac27) == 2
        assert {c.resources[0] for c in ac27} == {self.DF, self.OTHER_DF}


class TestChainAC029:
    """AC-029 — Untrusted trigger reaches a long-lived publish credential."""

    WF = ".github/workflows/release.yml"

    def test_fires_with_trigger_credential_integrity_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF),
            _f("GHA-050", self.WF),
            _f("GHA-021", self.WF),
        ])
        ac29 = [c for c in out if c.chain_id == "AC-029"]
        assert len(ac29) == 1
        assert ac29[0].severity is Severity.CRITICAL
        assert "T1195.002" in ac29[0].mitre_attack
        assert "T1606" in ac29[0].mitre_attack

    def test_fires_with_any_of_each_leg(self):
        # GHA-013 (issue_comment) + GHA-005 (long-lived AWS key) +
        # GHA-029 (integrity bypass) is a different combination of
        # the same three-leg shape; the chain should still fire.
        out = chains_pkg.evaluate([
            _f("GHA-013", self.WF),
            _f("GHA-005", self.WF),
            _f("GHA-029", self.WF),
        ])
        assert any(c.chain_id == "AC-029" for c in out)

    def test_does_not_fire_with_only_two_legs(self):
        # Trigger + credential without the integrity leg is bad but
        # not the AC-029 lane.
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF),
            _f("GHA-050", self.WF),
        ])
        assert not any(c.chain_id == "AC-029" for c in out)

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-050", ".github/workflows/b.yml"),
            _f("GHA-021", ".github/workflows/c.yml"),
        ])
        assert not any(c.chain_id == "AC-029" for c in out)

    def test_reachability_confirmed_when_anchor_jobs_intersect(self):
        # One job carries all three legs — the precise Ultralytics /
        # s1ngularity execution context.
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("release",)),
            _f("GHA-050", self.WF, job_anchors=("release",)),
            _f(
                "GHA-021",
                self.WF,
                job_anchors=("release",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac29 = next(c for c in out if c.chain_id == "AC-029")
        assert ac29.confirmed_reachable is True
        assert "release" in ac29.reachability_note
        assert ac29.confidence is Confidence.HIGH

    def test_reachability_unconfirmed_when_jobs_disjoint(self):
        # PR-head checkout in ``test``, publish credential in ``release``,
        # lockfile miss in ``build`` — three real findings on one
        # workflow but no shared execution context for the worm shape.
        out = chains_pkg.evaluate([
            _f("GHA-002", self.WF, job_anchors=("test",)),
            _f("GHA-050", self.WF, job_anchors=("release",)),
            _f(
                "GHA-021",
                self.WF,
                job_anchors=("build",),
                confidence=Confidence.MEDIUM,
            ),
        ])
        ac29 = next(c for c in out if c.chain_id == "AC-029")
        assert ac29.confirmed_reachable is False
        assert ac29.reachability_note == ""
        assert ac29.confidence is Confidence.MEDIUM

    def test_anchors_unioned_across_duplicate_findings_per_check(self):
        # Two distinct GHA-013 findings on the same workflow file,
        # each anchored to a different job. The previous dedup-by-
        # check_id code kept only the first and missed ``release``,
        # so the three-leg intersection couldn't confirm. Unioning
        # across duplicate findings recovers the shared job.
        out = chains_pkg.evaluate([
            _f("GHA-013", self.WF, job_anchors=("test",)),
            _f("GHA-013", self.WF, job_anchors=("release",)),
            _f("GHA-050", self.WF, job_anchors=("release",)),
            _f("GHA-021", self.WF, job_anchors=("release",)),
        ])
        ac29 = next(c for c in out if c.chain_id == "AC-029")
        assert ac29.confirmed_reachable is True
        assert "release" in ac29.reachability_note
        # Every per-check finding should appear in the chain's
        # triggering_findings (both GHA-013 entries, not just one).
        gha013_triggers = [
            t for t in ac29.triggering_findings if t.check_id == "GHA-013"
        ]
        assert len(gha013_triggers) == 2


class TestChainAC030:
    """AC-030 — Argo CD anonymous access meets wildcard RBAC."""

    RESOURCE = "argocd"

    def test_fires_when_both_legs_fail_on_same_instance(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", self.RESOURCE, severity=Severity.CRITICAL),
            _f("ARGOCD-004", self.RESOURCE, severity=Severity.CRITICAL),
        ])
        ac30 = [c for c in out if c.chain_id == "AC-030"]
        assert len(ac30) == 1
        chain = ac30[0]
        assert chain.severity is Severity.CRITICAL
        assert set(chain.triggering_check_ids) == {"ARGOCD-009", "ARGOCD-004"}
        assert "T1190" in chain.mitre_attack
        assert "T1078.001" in chain.mitre_attack
        assert "T1098.003" in chain.mitre_attack
        assert "initial-access" in chain.kill_chain_phase
        assert "impact" in chain.kill_chain_phase

    def test_does_not_fire_without_argocd009(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-004", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-030" for c in out)

    def test_does_not_fire_without_argocd004(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-030" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", self.RESOURCE, passed=True),
            _f("ARGOCD-004", self.RESOURCE, passed=True),
        ])
        assert not any(c.chain_id == "AC-030" for c in out)

    def test_does_not_fire_when_legs_target_different_instances(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", "argocd-east"),
            _f("ARGOCD-004", "argocd-west"),
        ])
        assert not any(c.chain_id == "AC-030" for c in out)

    def test_narrative_names_both_configmaps(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", self.RESOURCE),
            _f("ARGOCD-004", self.RESOURCE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-030")
        assert "argocd-cm" in chain.narrative
        assert "argocd-rbac-cm" in chain.narrative

    def test_confidence_inherits_from_weakest_leg(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-009", self.RESOURCE, confidence=Confidence.HIGH),
            _f("ARGOCD-004", self.RESOURCE, confidence=Confidence.MEDIUM),
        ])
        chain = next(c for c in out if c.chain_id == "AC-030")
        assert chain.confidence is Confidence.MEDIUM


class TestChainAC031:
    """AC-031 — Argo CD untrusted PR generator meets wildcard source repos."""

    RESOURCE = "argocd"

    def test_fires_when_both_legs_fail_on_same_instance(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", self.RESOURCE, severity=Severity.HIGH),
            _f("ARGOCD-001", self.RESOURCE, severity=Severity.HIGH),
        ])
        ac31 = [c for c in out if c.chain_id == "AC-031"]
        assert len(ac31) == 1
        chain = ac31[0]
        assert chain.severity is Severity.CRITICAL
        assert set(chain.triggering_check_ids) == {"ARGOCD-006", "ARGOCD-001"}
        assert "T1195.002" in chain.mitre_attack
        assert "T1199" in chain.mitre_attack
        assert "T1078.004" in chain.mitre_attack
        assert "initial-access" in chain.kill_chain_phase
        assert "impact" in chain.kill_chain_phase

    def test_does_not_fire_without_argocd006(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-001", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-031" for c in out)

    def test_does_not_fire_without_argocd001(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-031" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", self.RESOURCE, passed=True),
            _f("ARGOCD-001", self.RESOURCE, passed=True),
        ])
        assert not any(c.chain_id == "AC-031" for c in out)

    def test_does_not_fire_when_legs_target_different_instances(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", "argocd-east"),
            _f("ARGOCD-001", "argocd-west"),
        ])
        assert not any(c.chain_id == "AC-031" for c in out)

    def test_narrative_names_pull_request_generator_and_source_repos(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", self.RESOURCE),
            _f("ARGOCD-001", self.RESOURCE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-031")
        assert "pullRequest" in chain.narrative
        assert "sourceRepos" in chain.narrative

    def test_recommendation_names_both_fixes(self):
        out = chains_pkg.evaluate([
            _f("ARGOCD-006", self.RESOURCE),
            _f("ARGOCD-001", self.RESOURCE),
        ])
        chain = next(c for c in out if c.chain_id == "AC-031")
        assert "sourceRepos" in chain.recommendation
        assert "filters:" in chain.recommendation or "branchMatch" in chain.recommendation


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
            "      AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK\n"
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

    def test_chains_require_reachability_filters_unmigrated_chains(
        self, tmp_path, monkeypatch,
    ):
        # Fixture deliberately produces multiple chains:
        #   * AC-001 (pull_request_target + PR-sha checkout + AWS creds)
        #     — split across two jobs so ``GHA-002`` anchors on
        #     ``build`` while ``GHA-005`` anchors on ``publish``;
        #     the anchor sets are disjoint, so
        #     ``confirmed_reachable=False`` (co-occurrence only).
        #   * AC-002 (GHA-003 + GHA-014 in the same ``release`` job) —
        #     reachability confirmed.
        # With the flag off both fire; with the flag on only AC-002
        # survives.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "name: ci\n"
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK\n"
            "      AWS_SECRET_ACCESS_KEY: notarealsecret/notarealsecret/notarealsecret\n"
            "    steps:\n"
            "      - run: aws s3 cp build/ s3://prod/\n"
        )
        # Same workflow file, different job: GHA-003 + GHA-014 anchored
        # on the same ``release`` job ID.
        (wf_dir / "deploy.yml").write_text(
            "name: deploy\n"
            "on: pull_request\n"
            "jobs:\n"
            "  release:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo \"PR: ${{ github.event.pull_request.title }}\"\n"
            "          kubectl apply -f k8s/\n"
        )
        monkeypatch.chdir(tmp_path)

        def _json_from_output(text: str) -> dict:
            i = text.index("{")
            return json.loads(text[i:])

        # Baseline: both AC-001 and AC-002 fire.
        result = CliRunner().invoke(scan, ["-p", "github", "-o", "json"])
        payload = _json_from_output(result.output)
        chain_ids = {c["chain_id"] for c in payload.get("chains", [])}
        assert "AC-001" in chain_ids
        assert "AC-002" in chain_ids
        ac002 = next(
            c for c in payload["chains"] if c["chain_id"] == "AC-002"
        )
        assert ac002["confirmed_reachable"] is True

        # With --chains-require-reachability: AC-001 (unreachable)
        # dropped, AC-002 (reachable) kept.
        result = CliRunner().invoke(scan, [
            "-p", "github", "-o", "json",
            "--chains-require-reachability",
        ])
        payload = _json_from_output(result.output)
        chain_ids = {c["chain_id"] for c in payload.get("chains", [])}
        assert "AC-001" not in chain_ids
        assert "AC-002" in chain_ids


class TestChainAC032:
    """AC-032 — cosign-verified-but-not-bound artifact to production deploy."""

    RESOURCE = "deploy.yml"

    def test_fires_when_both_legs_fail_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("GHA-100", self.RESOURCE),
            _f("GHA-098", self.RESOURCE),
        ])
        ac32 = [c for c in out if c.chain_id == "AC-032"]
        assert len(ac32) == 1
        chain = ac32[0]
        assert chain.severity is Severity.CRITICAL
        assert set(chain.triggering_check_ids) == {"GHA-100", "GHA-098"}
        assert "T1195.002" in chain.mitre_attack

    def test_does_not_fire_without_gha100(self):
        out = chains_pkg.evaluate([
            _f("GHA-098", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-032" for c in out)

    def test_does_not_fire_without_gha098(self):
        out = chains_pkg.evaluate([
            _f("GHA-100", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-032" for c in out)

    def test_does_not_fire_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-100", "verify.yml"),
            _f("GHA-098", "deploy.yml"),
        ])
        assert not any(c.chain_id == "AC-032" for c in out)

    def test_does_not_fire_when_legs_passed(self):
        out = chains_pkg.evaluate([
            _f("GHA-100", self.RESOURCE, passed=True),
            _f("GHA-098", self.RESOURCE, passed=True),
        ])
        assert not any(c.chain_id == "AC-032" for c in out)


class TestChainAC033:
    """AC-033 — environment-secret laundering to unprotected deploy job."""

    RESOURCE = "deploy.yml"

    def test_fires_when_both_legs_fail_on_same_workflow(self):
        out = chains_pkg.evaluate([
            _f("TAINT-009", self.RESOURCE),
            _f("GHA-098", self.RESOURCE),
        ])
        ac33 = [c for c in out if c.chain_id == "AC-033"]
        assert len(ac33) == 1
        chain = ac33[0]
        assert chain.severity is Severity.CRITICAL
        assert set(chain.triggering_check_ids) == {"TAINT-009", "GHA-098"}

    def test_does_not_fire_without_taint009(self):
        out = chains_pkg.evaluate([
            _f("GHA-098", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-033" for c in out)

    def test_does_not_fire_without_gha098(self):
        out = chains_pkg.evaluate([
            _f("TAINT-009", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-033" for c in out)

    def test_does_not_fire_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("TAINT-009", "auth.yml"),
            _f("GHA-098", "deploy.yml"),
        ])
        assert not any(c.chain_id == "AC-033" for c in out)


class TestChainAC034:
    """AC-034 — submodule-poisoned PR to credential exfiltration."""

    RESOURCE = "ci.yml"

    def test_fires_with_gha037(self):
        out = chains_pkg.evaluate([
            _f("GHA-102", self.RESOURCE),
            _f("GHA-037", self.RESOURCE),
        ])
        ac34 = [c for c in out if c.chain_id == "AC-034"]
        assert len(ac34) == 1
        chain = ac34[0]
        assert chain.severity is Severity.CRITICAL
        assert "GHA-102" in chain.triggering_check_ids

    def test_fires_with_gha004(self):
        out = chains_pkg.evaluate([
            _f("GHA-102", self.RESOURCE),
            _f("GHA-004", self.RESOURCE),
        ])
        ac34 = [c for c in out if c.chain_id == "AC-034"]
        assert len(ac34) == 1

    def test_does_not_fire_without_gha102(self):
        out = chains_pkg.evaluate([
            _f("GHA-037", self.RESOURCE),
            _f("GHA-004", self.RESOURCE),
        ])
        assert not any(c.chain_id == "AC-034" for c in out)

    def test_does_not_fire_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-102", "pr.yml"),
            _f("GHA-037", "ci.yml"),
        ])
        assert not any(c.chain_id == "AC-034" for c in out)

    def test_deduplicates_when_both_credential_checks_fire(self):
        out = chains_pkg.evaluate([
            _f("GHA-102", self.RESOURCE),
            _f("GHA-037", self.RESOURCE),
            _f("GHA-004", self.RESOURCE),
        ])
        ac34 = [c for c in out if c.chain_id == "AC-034"]
        assert len(ac34) == 1


# ── Cross-repo directional dedup ──────────────────────────────────────


class TestCrossRepoDirectionalDedup:
    """CXPC matchers run producer -> consumer, so X->Y and Y->X are
    distinct paths. The dedup key must be ordered, not min/max, or the
    reverse direction is silently dropped when two repos each satisfy
    both legs."""

    def test_both_directions_emitted(self):
        wf = ".github/workflows/x.yml"
        findings_by_repo = {
            "org/repo-x": [_f("TAINT-001", wf), _f("GHA-002", wf)],
            "org/repo-y": [_f("TAINT-001", wf), _f("GHA-002", wf)],
        }
        out = chains_pkg.evaluate_cross_repo(
            findings_by_repo, enabled={"CXPC-004"},
        )
        assert len(out) == 2
        # Each chain pairs a different producer repo as the leg-A anchor.
        producers = {c.resources[0] for c in out}
        assert producers == {wf}
        assert all(c.chain_id == "CXPC-004" for c in out)


class TestChainAC037:
    """AC-037: AI agent applies attacker-influenced IaC to the cloud."""

    WF = ".github/workflows/iac.yml"

    def _ac037(self, findings):
        return [c for c in chains_pkg.evaluate(findings) if c.chain_id == "AC-037"]

    def test_gha058_plus_gha111_fires_critical(self):
        out = self._ac037([_f("GHA-058", self.WF), _f("GHA-111", self.WF)])
        assert len(out) == 1
        assert out[0].severity is Severity.CRITICAL
        assert out[0].triggering_check_ids == ["GHA-058", "GHA-111"]
        assert out[0].resources == [self.WF]

    def test_gha103_plus_gha111_fires(self):
        out = self._ac037([_f("GHA-103", self.WF), _f("GHA-111", self.WF)])
        assert len(out) == 1
        assert out[0].triggering_check_ids == ["GHA-103", "GHA-111"]

    def test_both_input_legs_dedup_to_one(self):
        out = self._ac037([
            _f("GHA-058", self.WF), _f("GHA-103", self.WF), _f("GHA-111", self.WF),
        ])
        assert len(out) == 1
        # Dedup keeps the GHA-058 leg per resource.
        assert out[0].triggering_check_ids == ["GHA-058", "GHA-111"]

    def test_no_chain_without_iac_apply(self):
        assert self._ac037([_f("GHA-058", self.WF)]) == []

    def test_no_chain_without_input_leg(self):
        assert self._ac037([_f("GHA-111", self.WF)]) == []

    def test_no_chain_across_different_workflows(self):
        out = self._ac037([
            _f("GHA-058", self.WF),
            _f("GHA-111", ".github/workflows/other.yml"),
        ])
        assert out == []

    def test_passed_iac_finding_does_not_chain(self):
        out = self._ac037([
            _f("GHA-058", self.WF), _f("GHA-111", self.WF, passed=True),
        ])
        assert out == []


class TestChainAC038:
    """AC-038: untrusted branch reaches OIDC trusted publish."""

    WF = ".github/workflows/release.yml"

    def _ac038(self, findings):
        return [c for c in chains_pkg.evaluate(findings) if c.chain_id == "AC-038"]

    def test_same_job_fires_critical_confirmed(self):
        out = self._ac038([
            _f("GHA-113", self.WF, job_anchors=("release",)),
            _f("GHA-114", self.WF, job_anchors=("release",)),
        ])
        assert len(out) == 1
        assert out[0].severity is Severity.CRITICAL
        assert out[0].triggering_check_ids == ["GHA-113", "GHA-114"]
        assert out[0].resources == [self.WF]
        assert out[0].confirmed_reachable is True
        # Confirmed single-job reachability promotes to HIGH confidence.
        assert out[0].confidence is Confidence.HIGH

    def test_different_jobs_fires_unconfirmed(self):
        out = self._ac038([
            _f("GHA-113", self.WF, job_anchors=("oidc",),
               confidence=Confidence.MEDIUM),
            _f("GHA-114", self.WF, job_anchors=("publish",),
               confidence=Confidence.MEDIUM),
        ])
        assert len(out) == 1
        assert out[0].confirmed_reachable is False
        # Unconfirmed co-occurrence stays at the weakest leg's confidence.
        assert out[0].confidence is Confidence.MEDIUM

    def test_no_chain_without_oidc_leg(self):
        assert self._ac038([_f("GHA-114", self.WF, job_anchors=("release",))]) == []

    def test_no_chain_without_trigger_leg(self):
        assert self._ac038([_f("GHA-113", self.WF, job_anchors=("release",))]) == []

    def test_no_chain_across_different_workflows(self):
        out = self._ac038([
            _f("GHA-113", self.WF, job_anchors=("release",)),
            _f("GHA-114", ".github/workflows/other.yml", job_anchors=("release",)),
        ])
        assert out == []

    def test_passed_finding_does_not_chain(self):
        out = self._ac038([
            _f("GHA-113", self.WF, job_anchors=("release",)),
            _f("GHA-114", self.WF, job_anchors=("release",), passed=True),
        ])
        assert out == []


class TestAC039UntrustedTriggerBulkSecrets:
    """AC-039: untrusted trigger (GHA-002/009/013) reaches a
    bulk-secrets serialization (GHA-116) in the same workflow."""

    WF = ".github/workflows/pr.yml"

    def _ac039(self, findings):
        return [c for c in chains_pkg.evaluate(findings) if c.chain_id == "AC-039"]

    def test_fires_on_trigger_plus_dump(self):
        out = self._ac039([
            _f("GHA-002", self.WF),
            _f("GHA-116", self.WF),
        ])
        assert len(out) == 1
        assert out[0].severity is Severity.CRITICAL
        assert "GHA-002" in out[0].triggering_check_ids
        assert "GHA-116" in out[0].triggering_check_ids

    def test_confirmed_reachable_when_same_job(self):
        out = self._ac039([
            _f("GHA-013", self.WF, job_anchors=("build",)),
            _f("GHA-116", self.WF, job_anchors=("build",)),
        ])
        assert len(out) == 1
        assert out[0].confirmed_reachable is True
        assert out[0].confidence is Confidence.HIGH
        assert "build" in out[0].reachability_note

    def test_unconfirmed_when_different_jobs(self):
        out = self._ac039([
            _f("GHA-002", self.WF, job_anchors=("checkout",)),
            _f("GHA-116", self.WF, job_anchors=("dump",)),
        ])
        assert len(out) == 1
        assert out[0].confirmed_reachable is False

    def test_does_not_fire_without_dump_leg(self):
        out = self._ac039([_f("GHA-002", self.WF)])
        assert out == []

    def test_does_not_fire_without_trigger_leg(self):
        out = self._ac039([_f("GHA-116", self.WF)])
        assert out == []

    def test_does_not_fire_on_different_workflows(self):
        out = self._ac039([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-116", ".github/workflows/b.yml"),
        ])
        assert out == []

    def test_passed_finding_does_not_chain(self):
        out = self._ac039([
            _f("GHA-002", self.WF),
            _f("GHA-116", self.WF, passed=True),
        ])
        assert out == []
