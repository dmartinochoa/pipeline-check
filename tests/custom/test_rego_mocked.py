"""Mock-based unit tests for the Rego engine that run WITHOUT the ``opa``
binary on PATH.

The integration tests in ``test_rego_loader.py`` / ``test_rego_runner.py``
skip when ``opa`` is absent, so in CI (no opa) the loader / runner / errors
modules were near-uncovered, which is why they sat in
``.github/coveragerc-no-fleet``'s omit list. These tests exercise the same
code by mocking the only two external seams, ``shutil.which("opa")`` and
``subprocess.run``, plus testing every pure-logic helper directly. That
lets the three modules come off the omit list and be measured.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.checks.custom import (
    rego_errors,
    rego_loader,
    rego_runner,
)
from pipeline_check.core.checks.custom.rego_errors import (
    OpaNotFoundError,
    RegoRuleError,
    find_opa_binary,
)
from pipeline_check.core.checks.custom.rego_loader import (
    RegoRuleMetadata,
    _extract_package_path,
    _parse_annotation,
    _to_str_tuple,
    _validate_and_build,
    load_rego_rules,
)
from pipeline_check.core.checks.custom.rego_runner import (
    _build_rule_index,
    _default_resource,
    _parse_results,
    _process_deny_set,
    evaluate_rego_rules,
    make_passing_findings,
)
from pipeline_check.core.checks.rule import Rule

# ── helpers ─────────────────────────────────────────────────────────


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> SimpleNamespace:
    """A stand-in for ``subprocess.CompletedProcess``."""
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def _meta(
    rule_id: str = "TEST-001",
    *,
    provider: str = "github",
    package_path: str = "pipeline_check.github.test_001",
    severity: Severity = Severity.HIGH,
    source: str = "/tmp/policies/x.rego",
    cwe: tuple[str, ...] = ("CWE-829",),
    incident_refs: tuple[str, ...] = (),
    exploit_example: str | None = None,
) -> RegoRuleMetadata:
    rule = Rule(
        id=rule_id,
        title=f"{rule_id} title",
        severity=severity,
        recommendation="fix it",
        cwe=cwe,
        incident_refs=incident_refs,
        exploit_example=exploit_example,
    )
    return RegoRuleMetadata(
        rule=rule, provider=provider, package_path=package_path, source=source,
    )


def _inspect_annotation(
    rule_id: str = "TEST-001",
    *,
    title: str = "A rule",
    severity: str = "HIGH",
    provider: str = "github",
    scope: str = "package",
    custom_extra: dict[str, Any] | None = None,
    pkg_tail: str = "test_001",
) -> dict[str, Any]:
    custom: dict[str, Any] = {"id": rule_id, "severity": severity, "provider": provider}
    if custom_extra:
        custom.update(custom_extra)
    return {
        "annotations": {"title": title, "scope": scope, "custom": custom},
        "location": {"file": "/tmp/policies/x.rego", "row": 1, "col": 1},
        "path": [
            {"type": "var", "value": "data"},
            {"type": "string", "value": "pipeline_check"},
            {"type": "string", "value": provider},
            {"type": "string", "value": pkg_tail},
        ],
    }


# ══ rego_errors ═════════════════════════════════════════════════════


class TestFindOpaBinary:
    def test_returns_path_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(rego_errors.shutil, "which", lambda name: "/usr/bin/opa")
        assert find_opa_binary() == "/usr/bin/opa"

    def test_raises_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(rego_errors.shutil, "which", lambda name: None)
        with pytest.raises(OpaNotFoundError) as exc:
            find_opa_binary()
        # The message points the user at the install docs, not a bare name.
        assert "opa" in str(exc.value).lower()


# ══ rego_loader: pure helpers ═══════════════════════════════════════


class TestExtractPackagePath:
    def test_valid_path_drops_data_prefix(self) -> None:
        path = [
            {"type": "var", "value": "data"},
            {"type": "string", "value": "pipeline_check"},
            {"type": "string", "value": "github"},
            {"type": "string", "value": "test_001"},
        ]
        assert _extract_package_path(path) == "pipeline_check.github.test_001"

    def test_non_list_returns_empty(self) -> None:
        assert _extract_package_path("nope") == ""
        assert _extract_package_path(None) == ""


class TestToStrTuple:
    def test_list_becomes_tuple_of_str(self) -> None:
        assert _to_str_tuple(["CWE-829", 22]) == ("CWE-829", "22")

    def test_bare_string_wraps(self) -> None:
        assert _to_str_tuple("CICD-SEC-3") == ("CICD-SEC-3",)

    def test_other_returns_empty(self) -> None:
        assert _to_str_tuple(None) == ()
        assert _to_str_tuple("") == ()


class TestParseAnnotation:
    def test_valid_returns_metadata(self) -> None:
        meta = _parse_annotation(_inspect_annotation(custom_extra={
            "recommendation": "Pin it", "cwe": ["CWE-829"], "owasp": ["CICD-SEC-3"],
        }))
        assert meta is not None
        assert meta.rule.id == "TEST-001"
        assert meta.provider == "github"
        assert meta.rule.severity == Severity.HIGH
        assert meta.rule.cwe == ("CWE-829",)
        assert meta.package_path == "pipeline_check.github.test_001"

    def test_non_package_scope_skipped(self) -> None:
        assert _parse_annotation(_inspect_annotation(scope="rule")) is None

    def test_inner_not_dict_skipped(self) -> None:
        assert _parse_annotation({"annotations": "oops"}) is None

    def test_custom_not_dict_skipped(self) -> None:
        ann = _inspect_annotation()
        ann["annotations"]["custom"] = "nope"
        assert _parse_annotation(ann) is None

    def test_missing_id_skipped(self) -> None:
        ann = _inspect_annotation()
        ann["annotations"]["custom"].pop("id")
        assert _parse_annotation(ann) is None


class TestValidateAndBuild:
    def _build(self, **over: Any) -> RegoRuleMetadata:
        kw: dict[str, Any] = dict(
            source="/tmp/x.rego", title="T", description="",
            rule_id="TEST-001", severity_str="HIGH", provider="github",
            package_path="pipeline_check.github.test_001", custom={},
        )
        kw.update(over)
        return _validate_and_build(**kw)

    def test_missing_title_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="title"):
            self._build(title="")

    def test_bad_id_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="must match"):
            self._build(rule_id="not-an-id")

    def test_bad_severity_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="severity"):
            self._build(severity_str="SPICY")

    def test_missing_provider_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="provider"):
            self._build(provider="")

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(RegoRuleError, match="not a recognized provider"):
            self._build(provider="myci")

    def test_valid_carries_custom_fields(self) -> None:
        meta = self._build(custom={
            "recommendation": "do x", "docs_note": "note",
            "cwe": ["CWE-1"], "owasp": ["O-1"], "esf": ["E-1"],
        })
        assert meta.rule.recommendation == "do x"
        assert meta.rule.cwe == ("CWE-1",)
        assert meta.rule.owasp == ("O-1",)
        assert meta.rule.esf == ("E-1",)


# ══ rego_loader: subprocess-mocked entry points ═════════════════════


class TestRunOpaInspect:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, **kw: Any) -> None:
        monkeypatch.setattr(rego_loader.subprocess, "run", lambda *a, **k: _completed(**kw))

    def test_success_collects_annotations(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = tmp_path / "x.rego"
        f.write_text("package pipeline_check.github.test_001\n", encoding="utf-8")
        self._patch(monkeypatch, stdout=json.dumps({"annotations": [_inspect_annotation()]}))
        out = rego_loader._run_opa_inspect("/fake/opa", [f])
        assert len(out) == 1 and out[0]["annotations"]["custom"]["id"] == "TEST-001"

    def test_nonzero_returncode_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = tmp_path / "x.rego"
        f.write_text("x\n", encoding="utf-8")
        self._patch(monkeypatch, returncode=1, stderr="parse error")
        with pytest.raises(RegoRuleError, match="opa inspect failed"):
            rego_loader._run_opa_inspect("/fake/opa", [f])

    def test_invalid_json_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = tmp_path / "x.rego"
        f.write_text("x\n", encoding="utf-8")
        self._patch(monkeypatch, stdout="not json")
        with pytest.raises(RegoRuleError, match="invalid JSON"):
            rego_loader._run_opa_inspect("/fake/opa", [f])

    def test_opa_missing_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = tmp_path / "x.rego"
        f.write_text("x\n", encoding="utf-8")
        def boom(*a: Any, **k: Any) -> Any:
            raise FileNotFoundError
        monkeypatch.setattr(rego_loader.subprocess, "run", boom)
        with pytest.raises(OpaNotFoundError):
            rego_loader._run_opa_inspect("/fake/opa", [f])


class TestLoadRegoRulesMocked:
    def _setup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, annotations: list[dict[str, Any]],
    ) -> Any:
        f = tmp_path / "x.rego"
        f.write_text("package pipeline_check.github.test_001\n", encoding="utf-8")
        monkeypatch.setattr(rego_loader, "_find_opa", lambda: "/fake/opa")
        monkeypatch.setattr(
            rego_loader.subprocess, "run",
            lambda *a, **k: _completed(stdout=json.dumps({"annotations": annotations})),
        )
        return f

    def test_none_paths_returns_empty(self) -> None:
        out = load_rego_rules(None)
        assert out.rules == [] and out.by_provider == {}

    def test_groups_by_provider(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = self._setup(monkeypatch, tmp_path, [
            _inspect_annotation("TEST-001", provider="github", pkg_tail="test_001"),
            _inspect_annotation("TEST-002", provider="gitlab", pkg_tail="test_002"),
        ])
        out = load_rego_rules([str(f)])
        assert {"github", "gitlab"} <= set(out.by_provider)
        assert {r.id for r in out.rules} == {"TEST-001", "TEST-002"}

    def test_builtin_collision_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = self._setup(monkeypatch, tmp_path, [_inspect_annotation("TEST-001")])
        with pytest.raises(RegoRuleError, match="built-in"):
            load_rego_rules([str(f)], builtin_ids={"TEST-001"})

    def test_yaml_collision_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = self._setup(monkeypatch, tmp_path, [_inspect_annotation("TEST-001")])
        with pytest.raises(RegoRuleError, match="YAML custom rule"):
            load_rego_rules([str(f)], yaml_custom_ids={"TEST-001"})

    def test_duplicate_rego_id_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        f = self._setup(monkeypatch, tmp_path, [
            _inspect_annotation("TEST-001", pkg_tail="a"),
            _inspect_annotation("TEST-001", pkg_tail="b"),
        ])
        with pytest.raises(RegoRuleError, match="already"):
            load_rego_rules([str(f)])


# ══ rego_runner: pure helpers ═══════════════════════════════════════


class TestBuildRuleIndex:
    def test_indexes_by_id_pkg_and_tail(self) -> None:
        meta = _meta("TEST-001", package_path="pipeline_check.github.test_001")
        idx = _build_rule_index([meta])
        assert idx["TEST-001"] is meta
        assert idx["pipeline_check.github.test_001"] is meta
        assert idx["test_001"] is meta


class TestDefaultResource:
    def test_top_level_path(self) -> None:
        assert _default_resource({"path": ".github/workflows/ci.yml"}) == ".github/workflows/ci.yml"

    def test_single_manifest_path(self) -> None:
        data = {"manifests": [{"path": "k8s/deploy.yaml", "kind": "Deployment"}]}
        assert _default_resource(data) == "k8s/deploy.yaml"

    def test_multiple_manifests_are_ambiguous(self) -> None:
        data = {"manifests": [{"path": "a.yaml"}, {"path": "b.yaml"}]}
        assert _default_resource(data) == "<unknown>"

    def test_nothing_known(self) -> None:
        assert _default_resource({}) == "<unknown>"


class TestProcessDenySet:
    def test_string_item_uses_rule_severity(self) -> None:
        findings: list[Finding] = []
        _process_deny_set(["bad thing"], _meta(severity=Severity.LOW), {"path": "f.yml"}, findings)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "TEST-001" and f.severity == Severity.LOW
        assert f.resource == "f.yml" and not f.passed

    def test_dict_item_severity_override(self) -> None:
        findings: list[Finding] = []
        item = {"msg": "boom", "resource": "x.yml", "severity": "critical"}
        _process_deny_set([item], _meta(severity=Severity.LOW), {}, findings)
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].resource == "x.yml"

    def test_dict_invalid_severity_falls_back(self) -> None:
        findings: list[Finding] = []
        _process_deny_set([{"msg": "m", "severity": "spicy"}], _meta(severity=Severity.HIGH), {}, findings)
        assert findings[0].severity == Severity.HIGH

    def test_dict_empty_msg_skipped(self) -> None:
        findings: list[Finding] = []
        _process_deny_set([{"resource": "x"}], _meta(), {}, findings)
        assert findings == []

    def test_non_str_non_dict_skipped(self) -> None:
        findings: list[Finding] = []
        _process_deny_set([42, None], _meta(), {}, findings)
        assert findings == []

    def test_no_metadata_uses_rego_000(self) -> None:
        findings: list[Finding] = []
        _process_deny_set(["orphan"], None, {"path": "f.yml"}, findings)
        assert findings[0].check_id == "REGO-000"
        assert findings[0].severity == Severity.MEDIUM


class TestParseResults:
    def _raw(self, value: Any) -> dict[str, Any]:
        return {"result": [{"expressions": [{"value": value}]}]}

    def test_with_denials(self) -> None:
        meta = _meta("TEST-001", package_path="pipeline_check.github.test_001")
        idx = _build_rule_index([meta])
        raw = self._raw({"github": {"test_001": {"deny": ["bad"]}}})
        findings = _parse_results(raw, idx, {"path": "f.yml"})
        assert len(findings) == 1 and findings[0].check_id == "TEST-001"

    def test_result_not_list(self) -> None:
        assert _parse_results({"result": "nope"}, {}, {}) == []

    def test_expressions_not_list(self) -> None:
        assert _parse_results({"result": [{"expressions": "x"}]}, {}, {}) == []

    def test_value_not_dict(self) -> None:
        assert _parse_results(self._raw("scalar"), {}, {}) == []

    def test_meta_fallback_by_package_suffix(self) -> None:
        # rule_index has no bare ``test_001`` key path match by pkg name, but
        # the package_path ``.test_001`` suffix resolves it.
        meta = _meta("TEST-001", package_path="custom.deep.test_001")
        idx = {"TEST-001": meta, "custom.deep.test_001": meta}
        raw = self._raw({"github": {"test_001": {"deny": ["bad"]}}})
        findings = _parse_results(raw, idx, {})
        assert findings[0].check_id == "TEST-001"

    def test_non_dict_packages_skipped(self) -> None:
        raw = self._raw({"github": "not-a-dict"})
        assert _parse_results(raw, {}, {}) == []


class TestMakePassingFindings:
    def test_excludes_denied_includes_rest(self) -> None:
        rules = [_meta("TEST-001"), _meta("TEST-002", package_path="pipeline_check.github.test_002")]
        out = make_passing_findings(rules, deny_rule_ids={"TEST-001"}, default_resource="repo")
        assert {f.check_id for f in out} == {"TEST-002"}
        assert out[0].passed and out[0].resource == "repo"

    def test_carries_optional_meta(self) -> None:
        rules = [_meta("TEST-009", incident_refs=("GHSA-x",), exploit_example="poc")]
        out = make_passing_findings(rules, deny_rule_ids=set(), default_resource="r")
        assert out[0].cwe == ["CWE-829"]
        assert getattr(out[0], "incident_refs", None) == ["GHSA-x"]
        assert getattr(out[0], "exploit_example", None) == "poc"


# ══ rego_runner: evaluate_rego_rules (subprocess-mocked) ═════════════


class TestEvaluateRegoRules:
    def test_empty_rules_short_circuits(self) -> None:
        assert evaluate_rego_rules([], {"path": "f"}) == []

    def test_evaluates_with_mocked_opa(self, monkeypatch: pytest.MonkeyPatch) -> None:
        meta = _meta("TEST-001", package_path="pipeline_check.github.test_001")
        eval_out = {"result": [{"expressions": [{"value": {
            "github": {"test_001": {"deny": ["Job build uses an unpinned action"]}},
        }}]}]}
        monkeypatch.setattr(
            rego_runner.subprocess, "run",
            lambda *a, **k: _completed(stdout=json.dumps(eval_out)),
        )
        # Pass opa_binary explicitly so find_opa_binary() is never reached.
        findings = evaluate_rego_rules([meta], {"path": "f.yml"}, opa_binary="/fake/opa")
        assert len(findings) == 1
        assert findings[0].check_id == "TEST-001" and not findings[0].passed

    def test_eval_nonzero_returncode_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            rego_runner.subprocess, "run",
            lambda *a, **k: _completed(returncode=1, stderr="bad policy"),
        )
        with pytest.raises(RegoRuleError, match="opa eval failed"):
            evaluate_rego_rules([_meta()], {"path": "f"}, opa_binary="/fake/opa")

    def test_eval_invalid_json_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            rego_runner.subprocess, "run",
            lambda *a, **k: _completed(stdout="["),
        )
        with pytest.raises(RegoRuleError, match="invalid JSON"):
            evaluate_rego_rules([_meta()], {"path": "f"}, opa_binary="/fake/opa")

    def test_eval_opa_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*a: Any, **k: Any) -> Any:
            raise FileNotFoundError
        monkeypatch.setattr(rego_runner.subprocess, "run", boom)
        with pytest.raises(OpaNotFoundError):
            evaluate_rego_rules([_meta()], {"path": "f"}, opa_binary="/fake/opa")
