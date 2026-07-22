"""Regression tests from the 2026-07 rule audit (Pulumi)."""
from __future__ import annotations

from pipeline_check.core.checks.pulumi.base import (
    PulumiContext,
    PulumiProject,
    PulumiSource,
)
from pipeline_check.core.checks.pulumi.rules import (
    pulumi006_stack_reference_unguarded as p6,
)
from pipeline_check.core.checks.pulumi.rules import (
    pulumi009_runtime_source_mismatch as p9,
)


def _project(path="a/Pulumi.yaml", runtime="python"):
    return PulumiProject(path=path, text="", name="a", runtime=runtime,
                         backend_url=None, data={}, parsed_ok=True)


def _ctx(sources, projects=None):
    return PulumiContext(projects=projects or [_project()], stacks=[],
                         sources=sources)


def test_pulumi006_helper_substring_not_flagged():
    helper = _ctx([PulumiSource(path="a/index.py",
                                text="ref = getStackReference('prod')\n",
                                runtime="python")])
    assert p6.check(helper).passed is True
    real = _ctx([PulumiSource(path="a/index.py",
                              text="ref = StackReference('prod')\n",
                              runtime="python")])
    assert p6.check(real).passed is False


def test_pulumi009_runtime_scan_is_project_scoped():
    # Project A (no python sources) must be flagged even when sibling B
    # supplies a .py file.
    pa = _project("a/Pulumi.yaml")
    pb = _project("b/Pulumi.yaml")
    ctx = PulumiContext(
        projects=[pa, pb], stacks=[],
        sources=[PulumiSource(path="b/__main__.py", text="", runtime="python")],
    )
    f = p9.check(ctx)
    assert f.passed is False
    assert "a/Pulumi.yaml" in f.description
