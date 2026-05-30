"""Per-rule unit tests for PULUMI-011..013 (Pulumi plugin + dynamic
provider pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.pulumi.base import PulumiContext
from pipeline_check.core.checks.pulumi.pipelines import PulumiChecks


def _scan(project_root: pathlib.Path) -> dict:
    ctx = PulumiContext.from_path(str(project_root))
    return {f.check_id: f for f in PulumiChecks(ctx).run()}


def _write_project(
    root: pathlib.Path,
    *,
    project_yaml: str = "name: my-app\nruntime: python\n",
    stack_yamls: dict[str, str] | None = None,
    sources: dict[str, str] | None = None,
) -> None:
    (root / "Pulumi.yaml").write_text(project_yaml, encoding="utf-8")
    for stack_name, body in (stack_yamls or {}).items():
        (root / f"Pulumi.{stack_name}.yaml").write_text(
            body, encoding="utf-8",
        )
    for relpath, body in (sources or {}).items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


# ── PULUMI-011 ──────────────────────────────────────────────────


class TestPULUMI011PluginCustomServer:
    def test_fires_on_provider_server_override(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                "    - name: aws\n"
                "      version: 6.18.0\n"
                "      server: https://downloads.evil.example/pulumi\n"
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-011"].passed

    def test_fires_on_analyzer_server_override(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  analyzers:\n"
                "    - name: policy\n"
                "      version: 1.2.3\n"
                "      server: https://mirror.example/pulumi\n"
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-011"].passed

    def test_passes_without_server_override(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                "    - name: aws\n"
                "      version: 6.18.0\n"
            ),
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-011"].passed

    def test_passes_when_no_plugins_block(self, tmp_path):
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-011"].passed


# ── PULUMI-012 ──────────────────────────────────────────────────


class TestPULUMI012PluginVersionUnpinned:
    def test_fires_on_missing_version(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                "    - name: aws\n"
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-012"].passed

    def test_fires_on_floating_version(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                '    - name: aws\n'
                '      version: "^6.0.0"\n'
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-012"].passed

    def test_passes_on_exact_version(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                "    - name: aws\n"
                "      version: 6.18.0\n"
            ),
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-012"].passed

    def test_skips_local_path_plugin(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "plugins:\n"
                "  providers:\n"
                "    - name: local\n"
                "      path: ./bin/pulumi-resource-local\n"
            ),
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-012"].passed

    def test_passes_when_no_plugins_block(self, tmp_path):
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-012"].passed


# ── PULUMI-013 ──────────────────────────────────────────────────


class TestPULUMI013DynamicProvider:
    def test_fires_on_python_dynamic_provider(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={
                "__main__.py": (
                    "import pulumi\n"
                    "class P(pulumi.dynamic.ResourceProvider):\n"
                    "    def create(self, props):\n"
                    "        return pulumi.dynamic.CreateResult("
                    "'id', props)\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-013"].passed

    def test_fires_on_node_dynamic_namespace(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: nodejs\n",
            sources={
                "index.ts": (
                    'import * as pulumi from "@pulumi/pulumi";\n'
                    "const p: pulumi.dynamic.ResourceProvider = {\n"
                    "  async create(inputs) { return { id: 'x', "
                    "outs: inputs }; },\n"
                    "};\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-013"].passed

    def test_passes_on_clean_python_source(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={
                "__main__.py": (
                    "import pulumi\n"
                    "pulumi.export('out', 'value')\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-013"].passed

    def test_passes_when_no_sources(self, tmp_path):
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-013"].passed
