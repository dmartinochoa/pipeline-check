"""Per-rule unit tests for HELM-015..017 (OCI / values / template pack)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.helm.base import HelmContext
from pipeline_check.core.checks.helm.charts import Chart
from pipeline_check.core.checks.helm.rules.helm015_oci_dependency_not_digest_pinned import (
    check as check_helm015,
)
from pipeline_check.core.checks.helm.rules.helm016_values_default_secret import (
    check as check_helm016,
)
from pipeline_check.core.checks.helm.rules.helm017_template_tpl_values_injection import (
    check as check_helm017,
)

_DIGEST = "sha256:" + "a" * 64


def _ctx(*charts: Chart) -> HelmContext:
    ctx = HelmContext([])
    ctx.charts = list(charts)
    return ctx


def _chart(
    name: str = "demo",
    api_version: str = "v2",
    dependencies: list[dict[str, Any]] | None = None,
    chart_lock: dict[str, Any] | None = None,
    values: dict[str, Any] | None = None,
    templates: list[tuple[str, str]] | None = None,
) -> Chart:
    cy: dict[str, Any] = {"name": name, "apiVersion": api_version}
    if dependencies is not None:
        cy["dependencies"] = dependencies
    return Chart(
        path=f"/fake/{name}",
        chart_yaml_path=f"/fake/{name}/Chart.yaml",
        chart_yaml=cy,
        chart_lock=chart_lock,
        values=values or {},
        values_path=f"/fake/{name}/values.yaml" if values else None,
        templates=tuple(templates or ()),
    )


# ── HELM-015 (OCI dependency not digest-pinned) ─────────────────


class TestHELM015:
    def test_fires_on_oci_dep_without_lock_digest(self):
        chart = _chart(dependencies=[{
            "name": "redis", "version": "18.1.5",
            "repository": "oci://registry-1.docker.io/bitnamicharts",
        }])
        f = check_helm015(_ctx(chart))
        assert not f.passed
        assert "redis" in f.description

    def test_passes_when_lock_has_digest(self):
        chart = _chart(
            dependencies=[{
                "name": "redis", "version": "18.1.5",
                "repository": "oci://registry-1.docker.io/bitnamicharts",
            }],
            chart_lock={"dependencies": [
                {"name": "redis", "version": "18.1.5", "digest": _DIGEST},
            ]},
        )
        f = check_helm015(_ctx(chart))
        assert f.passed

    def test_passes_when_version_is_digest_ref(self):
        chart = _chart(dependencies=[{
            "name": "redis", "version": f"18.1.5@{_DIGEST}",
            "repository": "oci://registry-1.docker.io/bitnamicharts",
        }])
        f = check_helm015(_ctx(chart))
        assert f.passed

    def test_ignores_non_oci_dependency(self):
        chart = _chart(dependencies=[{
            "name": "redis", "version": "18.1.5",
            "repository": "https://charts.bitnami.com/bitnami",
        }])
        f = check_helm015(_ctx(chart))
        assert f.passed


# ── HELM-016 (values.yaml default secret) ───────────────────────


class TestHELM016:
    def test_fires_on_real_default_password(self):
        chart = _chart(values={"auth": {"rootPassword": "S3cr3t-Pa55w0rd!"}})
        f = check_helm016(_ctx(chart))
        assert not f.passed
        assert "auth.rootPassword" in f.description

    def test_passes_on_empty_default(self):
        chart = _chart(values={"auth": {"rootPassword": ""}})
        f = check_helm016(_ctx(chart))
        assert f.passed

    def test_passes_on_existing_secret_reference(self):
        chart = _chart(values={"auth": {"existingSecret": "my-secret"}})
        f = check_helm016(_ctx(chart))
        assert f.passed

    def test_passes_on_templated_value(self):
        chart = _chart(values={"auth": {"password": "{{ .Values.x }}"}})
        f = check_helm016(_ctx(chart))
        assert f.passed

    def test_passes_on_placeholder_value(self):
        chart = _chart(values={"auth": {"password": "changeme"}})
        f = check_helm016(_ctx(chart))
        assert f.passed

    def test_fires_on_token_in_list(self):
        chart = _chart(values={"envs": [{"apiToken": "ghp_realtokenvalue12345"}]})
        f = check_helm016(_ctx(chart))
        assert not f.passed


# ── HELM-017 (tpl of an untrusted value) ────────────────────────


class TestHELM017:
    def test_fires_on_tpl_values(self):
        tmpl = (
            "/fake/demo/templates/cm.yaml",
            "data:\n  x: {{ tpl .Values.greeting . }}\n",
        )
        chart = _chart(templates=[tmpl])
        f = check_helm017(_ctx(chart))
        assert not f.passed
        assert "cm.yaml" in f.description

    def test_passes_on_plain_values_render(self):
        tmpl = (
            "/fake/demo/templates/cm.yaml",
            "data:\n  x: {{ .Values.greeting | quote }}\n",
        )
        chart = _chart(templates=[tmpl])
        f = check_helm017(_ctx(chart))
        assert f.passed

    def test_passes_on_tpl_of_constant(self):
        tmpl = (
            "/fake/demo/templates/cm.yaml",
            'data:\n  x: {{ tpl "{{ .Release.Name }}" . }}\n',
        )
        chart = _chart(templates=[tmpl])
        f = check_helm017(_ctx(chart))
        assert f.passed

    def test_passes_on_commented_out_tpl(self):
        # A Go-template comment renders nothing; it must not be read as a
        # live tpl-of-.Values sink (2026-07 audit LOW FP).
        tmpl = (
            "/fake/demo/templates/cm.yaml",
            "data:\n  # x: {{/* tpl .Values.greeting . */}}\n",
        )
        chart = _chart(templates=[tmpl])
        f = check_helm017(_ctx(chart))
        assert f.passed

    def test_fires_on_tpl_of_values_via_variable(self):
        # A .Values value bound to a $var and then tpl-ed is the same SSTI
        # sink via an indirect shape (2026-07 audit LOW FN).
        tmpl = (
            "/fake/demo/templates/cm.yaml",
            "{{ $v := .Values.greeting }}\ndata:\n  x: {{ tpl $v . }}\n",
        )
        chart = _chart(templates=[tmpl])
        f = check_helm017(_ctx(chart))
        assert not f.passed
        assert "cm.yaml" in f.description
