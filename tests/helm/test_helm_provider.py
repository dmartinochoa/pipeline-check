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

import subprocess
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

        def fake_render(chart_path, **_):
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


class TestOfflineFallback:
    """When the helm binary is absent, the provider parses templates/*.yaml
    directly (Go-template expressions neutralized) so the K8S-* security
    rules still fire. Regression guard: a chart's privileged / hostPath
    bugs must not silently vanish just because helm isn't installed (the
    common case in CI images and dev machines)."""

    def _write_chart(self, root: Path) -> Path:
        (root / "Chart.yaml").write_text(
            "apiVersion: v2\nname: agent\nversion: 0.1.0\n", encoding="utf-8"
        )
        tpl = root / "templates"
        tpl.mkdir()
        # A literal privileged container guarded by a templated `if`, plus
        # a `{{ .Release.Name }}` interpolation in the name — the exact
        # shape of cicd-goat's helm scenarios.
        (tpl / "daemonset.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: DaemonSet\n"
            "metadata:\n"
            "  name: {{ .Release.Name }}-agent\n"
            "spec:\n"
            "  selector: {matchLabels: {app: agent}}\n"
            "  template:\n"
            "    metadata: {labels: {app: agent}}\n"
            "    spec:\n"
            "      {{- if .Values.enabled }}\n"
            "      containers:\n"
            "        - name: agent\n"
            "          image: alpine@sha256:" + "0" * 64 + "\n"
            "          securityContext:\n"
            "            privileged: true\n"
            "      {{- end }}\n",
            encoding="utf-8",
        )
        return root

    def test_offline_parse_fires_k8s_when_helm_missing(
        self, tmp_path, monkeypatch
    ):
        from pipeline_check.core.checks.helm import base as helm_base

        def no_helm(chart_path, **_):
            raise HelmRenderError("helm binary not found on PATH.")

        monkeypatch.setattr(helm_base, "render_chart", no_helm)

        chart = self._write_chart(tmp_path)
        scanner = Scanner(pipeline="helm", helm_path=str(chart))
        findings = scanner.run()
        failed = {f.check_id for f in findings if not f.passed}
        # K8S-005 = privileged container. Without the offline fallback the
        # rule never runs and this set holds only HELM-* metadata nits.
        assert "K8S-005" in failed, sorted(failed)

    def test_neutralize_drops_control_lines_keeps_literals(self):
        from pipeline_check.core.checks.helm.render import _neutralize_template

        out = _neutralize_template(
            "metadata:\n"
            "  name: {{ .Release.Name }}-x\n"
            "  {{- if .Values.on }}\n"
            "  privileged: true\n"
            "  {{- end }}\n"
        )
        assert "name: pipelinecheck-x" in out
        assert "privileged: true" in out
        assert "{{" not in out and "}}" not in out


class TestEndToEnd:
    """One real ``helm template`` invocation. Skipped when helm is missing."""

    def test_render_and_scan_fixture_chart(self):
        if not helm_available():
            pytest.skip("helm binary not on PATH")
        # GitHub-hosted Windows runners ship a chocolatey-shimmed
        # helm.exe whose ``version`` probe periodically hangs (seen
        # at 30s+ in CI) for reasons unrelated to scanner logic.
        # Skip only on the failure modes that actually indicate the
        # helm binary is unusable here (OSError / FileNotFoundError /
        # TimeoutExpired bubbled up as ``HelmRenderError.__cause__``).
        # A broken chart, a malformed --helm-set entry, or a helm
        # exit-non-zero is a real scanner-side bug and must propagate
        # so the suite reds on it.
        try:
            result = render_chart(FIXTURE_CHART)
        except HelmRenderError as exc:
            if isinstance(exc.__cause__, (OSError, subprocess.TimeoutExpired)):
                pytest.skip(f"helm not usable on this runner: {exc}")
            raise
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


class TestHelmSetValidation:
    """``--helm-set KEY=VALUE`` is passed to a subprocess via argv list,
    but helm's own ``--set`` parser uses ``,`` as a separator and
    interprets ``\\`` escapes, so a single override can smuggle others
    into the rendered manifest. The validator rejects metacharacters
    that enable smuggling or any shell expansion."""

    def setup_method(self):
        # ``_validate_set_overrides`` is module-private, but it's the
        # focused unit under test. Importing here keeps the public
        # ``render_chart`` test surface intact.
        from pipeline_check.core.checks.helm.render import _validate_set_overrides
        self._validate = _validate_set_overrides

    def test_accepts_simple_key_value(self):
        # Should not raise.
        self._validate(["replicas=3", "image.tag=v1.2.3"])

    def test_accepts_bracketed_list_index(self):
        # helm path syntax for lists.
        self._validate(["nodeSelector[0]=a"])

    def test_rejects_comma_in_value(self):
        with pytest.raises(HelmRenderError, match="metacharacter"):
            self._validate(["image=evil,securityContext.runAsRoot=true"])

    def test_rejects_command_substitution(self):
        with pytest.raises(HelmRenderError, match="metacharacter"):
            self._validate(["image=$(whoami)"])

    def test_rejects_backtick(self):
        with pytest.raises(HelmRenderError, match="metacharacter"):
            self._validate(["image=`whoami`"])

    def test_rejects_newline_in_value(self):
        with pytest.raises(HelmRenderError, match="metacharacter"):
            self._validate(["image=foo\nbar"])

    def test_rejects_missing_equals(self):
        with pytest.raises(HelmRenderError, match="KEY=VALUE"):
            self._validate(["lonelyKey"])

    def test_rejects_unsafe_key(self):
        with pytest.raises(HelmRenderError, match="unsafe characters"):
            self._validate(["evil key=foo"])

    def test_helm_path_without_chart_yaml_raises(self, tmp_path):
        with pytest.raises(ValueError, match="no Chart.yaml"):
            HelmContext.from_path(tmp_path)
