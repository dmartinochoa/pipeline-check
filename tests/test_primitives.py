"""Unit tests for the cross-provider detection primitives under
``pipeline_check/core/checks/_primitives/``.

These lock in the positive / negative behaviour for each pattern
catalogue. Per-provider rule modules are thin wrappers that call
these primitives, so the rule-level tests (see
``tests/test_workflow_fixtures.py``) exercise the wiring; these
tests exercise the primitive's logic in isolation without the YAML
loading round-trip.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._primitives import (
    lockfile_integrity,
    shell_eval,
)

# ──────────────────────────────────────────────────────────────────
# shell_eval
# ──────────────────────────────────────────────────────────────────


class TestShellEvalPositives:
    @pytest.mark.parametrize("text,kind", [
        ('eval "$CMD"', "eval"),
        ("eval $USER_INPUT", "eval"),
        ("eval ${VAR}", "eval"),
        # Single-quoted args are also risky — eval re-parses the
        # literal string and expansion happens on the re-parse.
        ("eval '$X'", "eval"),
        # Command-substitution whose inner command expands a variable.
        ('eval "$(curl $URL)"', "eval"),
        # Unquoted eval of command-substitution with a variable arg.
        ("eval $(curl $URL)", "eval"),
        ('sh -c "$CMD"', "sh-c"),
        ("sh -c $X", "sh-c"),
        ("bash -c ${CMD}", "sh-c"),
        ("sh -c '$X'", "sh-c"),
        ("sh -c $(cat $FILE)", "sh-c"),
        ('bash -c "$(echo $VAR)"', "sh-c"),
        ("result=`$TOOL --version`", "backtick"),
        ("out=$( $TOOL arg )", "cmdsub"),
    ])
    def test_risky_idiom_flagged(self, text, kind):
        hits = shell_eval.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)

    def test_dedup_single_hit_for_overlapping_eval_patterns(self):
        """``eval "$(curl $URL)"`` matches both the cmdsub-var regex
        and the var-in-quotes regex. The scan must collapse them so
        the finding description doesn't double-count."""
        hits = shell_eval.scan('eval "$(curl $URL)"')
        assert len(hits) == 1

    def test_multi_line_blob_counts_each_occurrence(self):
        blob = "eval $A\neval $B\nsh -c $C"
        hits = shell_eval.scan(blob)
        assert len(hits) == 3


class TestShellEvalNegatives:
    @pytest.mark.parametrize("text", [
        # Literal command substitution — idiomatic bootstrap.
        'eval "$(ssh-agent -s)"',
        # Literal shell-c body — no variable.
        'sh -c "echo hello"',
        # Literal command in $().
        "value=$(date)",
        # Echoing a variable without shell re-parse — safe.
        'echo "$USER"',
        # No shell metacharacters involved.
        "VAR=value",
    ])
    def test_safe_idiom_not_flagged(self, text):
        assert shell_eval.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# lockfile_integrity
# ──────────────────────────────────────────────────────────────────


class TestLockfilePositives:
    @pytest.mark.parametrize("text,kind", [
        # Git URL without SHA pin — lockfile cannot protect.
        ("pip install git+https://github.com/foo/bar.git", "git"),
        ("npm install git+ssh://git@github.com/foo/bar.git", "git"),
        ("cargo install --git https://github.com/foo/bar", "git"),
        # GitHub shorthand — resolves to default branch.
        ("npm install some-org/my-repo", "git"),
        # Local-path installs.
        ("pip install ./my-lib", "path"),
        ("pip install file:///srv/wheels/foo.whl", "path"),
        ("npm install /opt/shared/pkg", "path"),
        ("yarn add file:./local", "path"),
        # Direct tarball URLs.
        ("pip install https://example.com/pkg.tar.gz", "tarball"),
        ("npm install https://example.com/pkg.tgz", "tarball"),
    ])
    def test_bypass_flagged(self, text, kind):
        hits = lockfile_integrity.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)


class TestLockfileNegatives:
    @pytest.mark.parametrize("text", [
        # Registry install with version pin.
        "pip install requests==2.28.1",
        "npm install express",
        # Lockfile-enforcing install.
        "npm ci",
        # Git URL pinned to a commit SHA.
        "pip install git+https://github.com/foo/bar.git@" + "a" * 40,
        ("cargo install --git https://github.com/foo/bar --rev " + "a" * 40),
        # Bare ``.`` — current-package build, legitimate.
        "pip install .",
        # No install command at all.
        "echo 'installing'",
    ])
    def test_safe_install_not_flagged(self, text):
        assert lockfile_integrity.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# Integration sanity — both primitives exposed through the provider
# rule modules and picked up by the orchestrator.
# ──────────────────────────────────────────────────────────────────


def test_shell_eval_rule_registered_for_every_workflow_provider():
    """Every workflow provider should have a rule module calling
    the shell_eval primitive — easy regression guard if someone
    ships a new primitive and forgets to wire one provider."""
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-028",
        "pipeline_check.core.checks.gitlab.rules": "GL-026",
        "pipeline_check.core.checks.bitbucket.rules": "BB-026",
        "pipeline_check.core.checks.azure.rules": "ADO-027",
        "pipeline_check.core.checks.circleci.rules": "CC-027",
        "pipeline_check.core.checks.jenkins.rules": "JF-030",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"


def test_lockfile_integrity_rule_registered_for_every_workflow_provider():
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-029",
        "pipeline_check.core.checks.gitlab.rules": "GL-027",
        "pipeline_check.core.checks.bitbucket.rules": "BB-027",
        "pipeline_check.core.checks.azure.rules": "ADO-028",
        "pipeline_check.core.checks.circleci.rules": "CC-028",
        "pipeline_check.core.checks.jenkins.rules": "JF-031",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"
