"""Regression tests for the 2026-05-31 'Known issues / Low' bug sweep.

Each test pins a specific behavior that was wrong before the sweep and is
documented in the ROADMAP's ``Known issues`` section. Kept self-contained so
they exercise the fixed code paths directly rather than through a full scan.
"""
from __future__ import annotations

import types

import pytest

from pipeline_check.core import scanner
from pipeline_check.core.checks._primitives.secret_verifiers import jwt
from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.custom.evaluator import (
    PredicateError,
    compile_predicate,
)
from pipeline_check.core.checks.custom.rego_runner import _default_resource
from pipeline_check.core.checks.gitlab.resolver import GitLabIncludeFetcher
from pipeline_check.core.inline_ignore import extract_inline_ignores
from pipeline_check.core.sarif_ingest import _resolve_severity


def test_sarif_missing_level_defaults_to_warning_medium():
    # Absent level + no security-severity → MEDIUM (SARIF 2.1.0 defaults an
    # absent ``level`` to ``warning``), not INFO.
    assert _resolve_severity(None, None) is Severity.MEDIUM
    # An explicit ``level: none`` still maps to INFO.
    assert _resolve_severity("none", None) is Severity.INFO
    # An unrecognized level value also defaults to MEDIUM.
    assert _resolve_severity("bogus", None) is Severity.MEDIUM
    # Known levels are unchanged.
    assert _resolve_severity("error", None) is Severity.HIGH


def test_inline_ignore_multiword_reason_not_truncated():
    rules = extract_inline_ignores(
        "x.yml",
        "key: v  # pipeline-check: ignore[GHA-001] reason=accepted for now\n",
    )
    assert len(rules) == 1
    assert rules[0].check_id == "GHA-001"
    assert rules[0].reason == "accepted for now"


def test_evaluator_bool_is_not_a_number():
    pred = compile_predicate({"gt": {"path": "x", "value": 0}})
    assert pred({"x": 5}) is True
    # ``bool`` subclasses ``int``; a YAML ``true`` must not satisfy a numeric
    # comparison as ``1``.
    assert pred({"x": True}) is False
    with pytest.raises(PredicateError):
        compile_predicate({"gt": {"path": "x", "value": True}})


def test_evaluator_len_rejects_bool_value():
    with pytest.raises(PredicateError):
        compile_predicate({"len_eq": {"path": "x", "value": True}})


def test_jwt_userinfo_endpoints_use_correct_hosts():
    probes = dict(jwt._ISSUER_PROBES)
    # Microsoft Entra serves UserInfo from Microsoft Graph, Google from its
    # OIDC host — both absolute, not appended to the issuer.
    assert probes["login.microsoftonline.com"] == (
        "https://graph.microsoft.com/oidc/userinfo"
    )
    assert probes["accounts.google.com"] == (
        "https://openidconnect.googleapis.com/v1/userinfo"
    )
    # Issuer-hosted endpoints stay relative.
    assert probes["auth0.com"] == "/userinfo"


def test_gitlab_project_include_accepts_list_file(monkeypatch):
    fetcher = GitLabIncludeFetcher()
    seen: list[tuple] = []

    def _fake(project, file_path, ref):
        seen.append((project, file_path, ref))
        return f"# {file_path}".encode()

    monkeypatch.setattr(fetcher, "_fetch_one_file", _fake)
    out = fetcher._fetch_project(
        {"project": "grp/proj", "file": ["/a.yml", "b.yml"]},
    )
    # A list-valued ``file:`` fetches each entry and joins as a YAML stream
    # rather than 404-ing on a stringified list.
    assert out == b"# /a.yml\n---\n# b.yml"
    assert len(seen) == 2


def test_rego_default_resource_uses_k8s_manifest_path():
    # Top-level ``path`` (doc-list providers) wins.
    assert _default_resource({"path": "ci.yml"}) == "ci.yml"
    # K8s input has ``manifests`` and no top-level ``path``; a single
    # manifest path is used instead of ``<unknown>``.
    assert _default_resource(
        {"manifests": [{"path": "deploy.yaml", "kind": "Pod"}]},
    ) == "deploy.yaml"
    # Several distinct manifest paths can't be attributed to one deny string.
    assert _default_resource(
        {"manifests": [{"path": "a.yaml"}, {"path": "b.yaml"}]},
    ) == "<unknown>"
    # Empty / missing falls back to ``<unknown>``.
    assert _default_resource({"path": ""}) == "<unknown>"
    assert _default_resource({}) == "<unknown>"


def _tf_ctx(module_calls, resources):
    return types.SimpleNamespace(plan={
        "configuration": {"root_module": {"module_calls": module_calls}},
        "planned_values": {"root_module": {"resources": resources}},
    })


def test_terraform_diff_keeps_renamed_module_on_source_change():
    # ``module "vpc" { source = "./modules/networking" }`` — the call label
    # (vpc) differs from the source dir (networking). A change under the
    # source dir must keep the module's resources.
    ctx = _tf_ctx(
        {"vpc": {"source": "./modules/networking"}},
        [{"address": "module.vpc.aws_subnet.public"}],
    )
    scanner._filter_terraform_by_diff(ctx, {"modules/networking/main.tf"})
    kept = [
        r["address"]
        for r in ctx.plan["planned_values"]["root_module"]["resources"]
    ]
    assert kept == ["module.vpc.aws_subnet.public"]


def test_terraform_diff_drops_module_when_source_unchanged():
    ctx = _tf_ctx(
        {"vpc": {"source": "./modules/networking"}},
        [{"address": "module.vpc.aws_subnet.public"}],
    )
    scanner._filter_terraform_by_diff(ctx, {"modules/storage/main.tf"})
    kept = [
        r["address"]
        for r in ctx.plan["planned_values"]["root_module"]["resources"]
    ]
    assert kept == []
