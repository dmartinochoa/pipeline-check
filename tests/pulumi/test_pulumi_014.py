"""Per-rule unit tests for PULUMI-014 (unqualified ESC environment import)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.pulumi.base import PulumiContext
from pipeline_check.core.checks.pulumi.pipelines import PulumiChecks


def _scan(root: pathlib.Path, *, project: str, stacks: dict[str, str]):
    (root / "Pulumi.yaml").write_text(project, encoding="utf-8")
    for name, body in stacks.items():
        (root / f"Pulumi.{name}.yaml").write_text(body, encoding="utf-8")
    ctx = PulumiContext.from_path(str(root))
    return {f.check_id: f for f in PulumiChecks(ctx).run()}


_PROJECT = "name: my-app\nruntime: python\n"


class TestPULUMI014EscEnvironmentUnqualified:
    def test_fires_on_bare_environment_name(self, tmp_path):
        findings = _scan(tmp_path, project=_PROJECT, stacks={
            "prod": "environment:\n  - prod-secrets\nconfig:\n  aws:region: us-east-1\n",
        })
        assert not findings["PULUMI-014"].passed
        assert "prod-secrets" in findings["PULUMI-014"].description

    def test_passes_on_qualified_environment(self, tmp_path):
        findings = _scan(tmp_path, project=_PROJECT, stacks={
            "prod": "environment:\n  - myproject/prod-secrets\n",
        })
        assert findings["PULUMI-014"].passed

    def test_passes_when_no_environment(self, tmp_path):
        findings = _scan(tmp_path, project=_PROJECT, stacks={
            "prod": "config:\n  aws:region: us-east-1\n",
        })
        assert findings["PULUMI-014"].passed

    def test_fires_on_imports_form(self, tmp_path):
        findings = _scan(tmp_path, project=_PROJECT, stacks={
            "prod": "environment:\n  imports:\n    - shared-env\n",
        })
        assert not findings["PULUMI-014"].passed
