"""Helm provider tests.

Two layers:

1. Pure-Python tests against captured ``helm template`` output. These
   exercise the source-header parser, ``from_yaml_stream``, and the
   provider's reuse of the K8s rule pack. They never invoke the
   ``helm`` binary, so they run in any CI image and on contributor
   machines without Helm installed.

2. One end-to-end smoke test that actually invokes ``helm template``
   on the fixture chart at ``tests/fixtures/helm/sample/``. Skipped
   when the binary is missing — the unit tests above already cover
   the integration shape, so the e2e test is "trust but verify"
   rather than the only line of defense.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.helm.base import HelmContext
from pipeline_check.core.checks.helm.render import (
    HelmRenderError,
    _extract_source_templates,
    helm_available,
    render_chart,
)
from pipeline_check.core.checks.kubernetes.base import KubernetesContext
from pipeline_check.core.scanner import Scanner

REPO = Path(__file__).resolve().parent.parent.parent
FIXTURE_CHART = REPO / "tests" / "fixtures" / "helm" / "sample"


# Captured output of ``helm template release ./sample`` for the
# fixture chart. Stored as a literal so we don't shell out in the
# common-path tests.
RENDERED_SAMPLE = """\
---
# Source: sample/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: release
  template:
    metadata:
      labels:
        app: release
    spec:
      containers:
        - name: app
          image: "nginx:latest"
          securityContext:
            privileged: true
            runAsNonRoot: false
"""


class TestSourceHeaderParser:

    def test_extracts_chart_relative_template_path(self):
        sources = _extract_source_templates(RENDERED_SAMPLE)
        assert sources == ["sample/templates/deployment.yaml"]

    def test_handles_multiple_docs(self):
        text = (
            "---\n"
            "# Source: chart/templates/sa.yaml\n"
            "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: a}\n"
            "---\n"
            "# Source: chart/templates/deployment.yaml\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: b}\n"
            "spec: {selector: {matchLabels: {app: b}}, "
            "template: {metadata: {labels: {app: b}}, spec: "
            "{containers: [{name: c, image: nginx@sha256:" + "0" * 64 + "}]}}}\n"
        )
        sources = _extract_source_templates(text)
        assert sources == [
            "chart/templates/sa.yaml",
            "chart/templates/deployment.yaml",
        ]

    def test_doc_without_source_header_yields_none(self):
        text = (
            "---\n"
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n"
        )
        assert _extract_source_templates(text) == [None]

    def test_empty_input_yields_empty_list(self):
        assert _extract_source_templates("") == []
        assert _extract_source_templates("\n\n") == []


class TestFromYamlStream:

    def test_parses_rendered_helm_output(self):
        sources = _extract_source_templates(RENDERED_SAMPLE)
        ctx = KubernetesContext.from_yaml_stream(
            RENDERED_SAMPLE,
            path_hint="sample",
            source_templates=sources,
        )
        assert len(ctx.manifests) == 1
        m = ctx.manifests[0]
        assert m.kind == "Deployment"
        assert m.source_template == "sample/templates/deployment.yaml"
        # Display string prefers source_template over the synthetic path.
        assert "sample/templates/deployment.yaml" in m.display

    def test_parse_error_lands_in_warnings(self):
        ctx = KubernetesContext.from_yaml_stream(
            "this: is\n  not: [valid yaml",
            path_hint="bad",
        )
        assert ctx.manifests == []
        assert ctx.warnings
        assert "YAML parse error" in ctx.warnings[0]


class TestProviderReusesK8sRules:
    """The whole point of the helm provider: K8S-* rules fire on rendered manifests."""

    def test_privileged_container_in_rendered_chart_fires_k8s005(
        self, monkeypatch
    ):
        # Stand in for ``render_chart`` so we don't need the helm
        # binary. The captured output above is what ``helm template``
        # produces against the fixture chart on a Helm 3 install.
        from pipeline_check.core.checks.helm import base as helm_base
        from pipeline_check.core.checks.helm.render import RenderResult

        def fake_render(chart_path, **_):  # noqa: ARG001
            return RenderResult(
                yaml=RENDERED_SAMPLE,
                source_templates=_extract_source_templates(RENDERED_SAMPLE),
            )

        monkeypatch.setattr(helm_base, "render_chart", fake_render)

        scanner = Scanner(pipeline="helm", helm_path=str(FIXTURE_CHART))
        findings = scanner.run()
        check_ids = {f.check_id for f in findings if not f.passed}
        # K8S-005 = privileged container. The fixture's deployment
        # sets privileged: true, so this is the load-bearing assertion.
        assert "K8S-005" in check_ids, (
            f"expected K8S-005 to fail on rendered chart; got "
            f"{sorted(check_ids)}"
        )
        k8s005 = next(f for f in findings if f.check_id == "K8S-005")
        # The fixture's rendered deployment is named ``release-app``;
        # the finding's offender list should mention it, confirming
        # the rule actually saw the rendered manifest rather than an
        # empty pod-spec list.
        assert "release-app" in k8s005.description
        # The Manifest itself carries the chart-relative source path
        # so reporters / inventory can surface the template file.
        ctx = scanner._context
        assert any(
            (m.source_template or "").endswith("templates/deployment.yaml")
            for m in ctx.manifests
        )


class TestEndToEnd:
    """One real ``helm template`` invocation. Skipped when helm is missing."""

    def test_render_and_scan_fixture_chart(self):
        if not helm_available():
            pytest.skip("helm binary not on PATH")
        # GitHub-hosted Windows runners ship a chocolatey-shimmed
        # helm.exe whose ``version`` probe periodically hangs (seen
        # at 30s+ in CI) for reasons unrelated to scanner logic.
        # Treat any probe / render failure as "helm not usable here"
        # and skip rather than red the whole suite over a runner
        # quirk. The pure-Python tests above still cover the parser
        # and the K8s-rule reuse, which is what this provider's
        # behavior actually depends on.
        try:
            result = render_chart(FIXTURE_CHART)
        except HelmRenderError as exc:
            pytest.skip(f"helm not usable on this runner: {exc}")
        assert result.yaml.strip(), "helm produced empty output"
        assert any(
            s and s.endswith("templates/deployment.yaml")
            for s in result.source_templates
        )
        ctx = HelmContext.from_path(FIXTURE_CHART)
        kinds = {m.kind for m in ctx.manifests}
        assert "Deployment" in kinds


class TestProviderErrors:

    def test_missing_helm_path_raises(self):
        from pipeline_check.core.providers import get
        provider = get("helm")
        assert provider is not None
        with pytest.raises(ValueError, match="--helm-path"):
            provider.build_context()

    def test_helm_path_without_chart_yaml_raises(self, tmp_path):
        with pytest.raises(ValueError, match="no Chart.yaml"):
            HelmContext.from_path(tmp_path)
