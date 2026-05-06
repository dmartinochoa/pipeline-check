"""Tests for the ``pipeline_check init`` scaffold template.

The template's docstring promises that every commented key is a real
config-file key. These tests pin that contract so a future config rename
(e.g. removing ``severity_threshold``, adding a new gate key) can't drift
silently — the test will fail with a clear "key in template not present
in config registry" error.
"""
from __future__ import annotations

import re

import pytest
import yaml

from pipeline_check.core import init_template
from pipeline_check.core.config import _GATE_KEYS, _TOPLEVEL_KEYS


def test_render_without_detected_pipeline_emits_commented_placeholder():
    out = init_template.render(None)
    # Pipeline line is commented and lists the supported provider names.
    assert "# pipeline: github    # aws | github | gitlab" in out
    assert "pipeline: " not in out.replace("# pipeline: ", "")


@pytest.mark.parametrize("name", [
    "github", "gitlab", "aws", "terraform", "cloudformation",
    "bitbucket", "azure", "jenkins", "circleci", "cloudbuild",
])
def test_render_with_detected_pipeline_uncomments_pipeline_line(name):
    out = init_template.render(name)
    # The active line is uncommented; the placeholder comment is gone.
    assert f"\npipeline: {name}\n" in out
    assert "# pipeline: github    " not in out


def test_rendered_template_is_valid_yaml():
    """The whole template must parse — comments stripped — without
    raising. Captures regressions where a stray `:` or quote slips
    into the scaffold."""
    out = init_template.render("github")
    loaded = yaml.safe_load(out)
    # Only ``pipeline`` and ``gate`` are uncommented; everything else
    # is a comment and won't surface in the parsed mapping.
    assert isinstance(loaded, dict)
    assert loaded["pipeline"] == "github"
    # ``gate`` block exists with no children (every gate key is
    # commented out by default).
    assert "gate" in loaded
    assert loaded["gate"] is None or loaded["gate"] == {}


_COMMENTED_KEY_RE = re.compile(r"^# (\w+):", re.MULTILINE)
_GATE_INDENTED_KEY_RE = re.compile(r"^  # (\w+):", re.MULTILINE)


def test_every_commented_top_level_key_is_a_real_config_key():
    out = init_template.render(None)
    # Skip the inline header comments that aren't keys (e.g.
    # "# pipeline-check.yml — configuration..."). The regex only
    # picks lines whose comment is a single word followed by ``:``.
    template_top_keys = set(_COMMENTED_KEY_RE.findall(out))
    # Some commented words aren't config keys (e.g. ``Filtering`` /
    # ``Output`` headers, but those don't end in ``:`` after a word).
    # Drop the section-header captures: we only want strings that
    # would parse as a YAML key.
    template_top_keys -= {"Filtering", "Output", "CI"}
    unknown = template_top_keys - _TOPLEVEL_KEYS
    assert not unknown, (
        f"init_template references unknown top-level config keys: "
        f"{sorted(unknown)}. Update either the template or "
        f"core.config._TOPLEVEL_KEYS."
    )


def test_every_commented_gate_key_is_a_real_gate_config_key():
    out = init_template.render(None)
    template_gate_keys = set(_GATE_INDENTED_KEY_RE.findall(out))
    unknown = template_gate_keys - _GATE_KEYS
    assert not unknown, (
        f"init_template's gate: block references unknown gate keys: "
        f"{sorted(unknown)}. Update either the template or "
        f"core.config._GATE_KEYS."
    )


def test_render_is_deterministic():
    """Two calls with the same input must produce identical bytes —
    the CLI relies on that for ``--config-check`` round-trips."""
    a = init_template.render("github")
    b = init_template.render("github")
    assert a == b
