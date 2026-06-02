"""Regression tests from the rule audit (Azure Pipelines fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.azure.rules import ado002_script_injection as ado002
from pipeline_check.core.checks.azure.rules import ado013_self_hosted_ephemeral as ado013
from pipeline_check.core.checks.azure.rules import ado027_shell_eval as ado027


class TestADO013SelfHostedEphemeral:
    def test_structured_demands_do_not_crash(self):
        # `demands:` entries are usually strings, but a structured entry
        # (a dict) used to crash " ".join(demands).
        doc = yaml.safe_load(
            "pool:\n"
            "  name: build-pool\n"
            "  demands:\n"
            "    - {name: gpu}\n"
            "steps: [{script: m}]\n"
        )
        f = ado013.check("azure-pipelines.yml", doc)
        # Structured demand with no ephemeral marker: the rule should fire
        # (passed False) without the str-join crash on the dict entry.
        assert f.passed is False


class TestADO002ScriptInjection:
    def test_prefix_var_does_not_fire(self):
        # Tainted var BR must NOT match a script that only references
        # $BRANCHX (a different, unrelated variable with the same prefix).
        doc = yaml.safe_load(
            "variables:\n"
            "  - name: BR\n"
            "    value: $(Build.SourceBranch)\n"
            "steps:\n"
            "  - script: echo $BRANCHX\n"
        )
        f = ado002.check("azure-pipelines.yml", doc)
        assert f.passed is True, (
            "ADO-002 should not flag $BRANCHX when only $BR is tainted"
        )

    def test_exact_tainted_var_fires(self):
        # $BR (exact match, word boundary) must still fire.
        doc = yaml.safe_load(
            "variables:\n"
            "  - name: BR\n"
            "    value: $(Build.SourceBranch)\n"
            "steps:\n"
            "  - script: echo $BR\n"
        )
        f = ado002.check("azure-pipelines.yml", doc)
        assert f.passed is False, "ADO-002 must flag a bare $BR reference"

    def test_braced_tainted_var_fires(self):
        # ${BR} must still fire.
        doc = yaml.safe_load(
            "variables:\n"
            "  - name: BR\n"
            "    value: $(Build.SourceBranch)\n"
            "steps:\n"
            "  - script: echo ${BR}\n"
        )
        f = ado002.check("azure-pipelines.yml", doc)
        assert f.passed is False, "ADO-002 must flag ${BR}"


class TestADO027ShellEval:
    def test_description_field_with_eval_does_not_fire(self):
        # A free-text string in variables.description containing
        # "eval $VAR" is not executed shell; it must not trigger ADO-027.
        doc = yaml.safe_load(
            "variables:\n"
            "  description: 'Use eval $VAR to configure dynamic steps'\n"
            "steps:\n"
            "  - script: echo hello\n"
        )
        f = ado027.check("azure-pipelines.yml", doc)
        assert f.passed is True, (
            "ADO-027 must not flag eval in a non-executed description string"
        )

    def test_eval_in_script_step_fires(self):
        # An actual bash step body with eval "$VAR" must still fire.
        doc = yaml.safe_load(
            "steps:\n"
            "  - bash: |\n"
            '      eval "$BUILD_CMD"\n'
        )
        f = ado027.check("azure-pipelines.yml", doc)
        assert f.passed is False, (
            "ADO-027 must flag eval with a variable in a bash step body"
        )
