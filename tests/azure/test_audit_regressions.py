"""Regression tests from the rule audit (Azure Pipelines fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.azure.rules import ado001_task_pinning as ado001
from pipeline_check.core.checks.azure.rules import ado013_self_hosted_ephemeral as ado013
from pipeline_check.core.checks.azure.rules import ado030_pool_injection as ado030


class TestADO030PoolInjection:
    def test_exploit_example_strong_check(self):
        # Both fragments previously used flow-mapping syntax
        # (``pool: { name: ${{ parameters.X }} }``), which raises a YAML
        # ParserError on the nested ``{{``. Rewritten to block-mapping form.
        # The Safe fragment hard-codes the pool name so the rule does not fire.
        vuln, safe = ado030.RULE.exploit_example.split("\n\n", 1)
        assert ado030.check("azure-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert ado030.check("azure-pipelines.yml", yaml.safe_load(safe)).passed is True

    def test_parameter_interpolation_fires(self):
        # Block-mapping form of the tainted pool must still trigger the rule.
        doc = yaml.safe_load(
            "parameters:\n"
            "  - name: targetPool\n"
            "    type: string\n"
            "    default: linux-pool\n"
            "jobs:\n"
            "  - job: build\n"
            "    pool:\n"
            "      name: ${{ parameters.targetPool }}\n"
            "    steps:\n"
            "      - bash: make build\n"
        )
        assert ado030.check("azure-pipelines.yml", doc).passed is False

    def test_hardcoded_pool_passes(self):
        # A literal pool name with no expression is safe.
        doc = yaml.safe_load(
            "jobs:\n"
            "  - job: build\n"
            "    pool:\n"
            "      name: linux-pool\n"
            "    steps:\n"
            "      - bash: make build\n"
        )
        assert ado030.check("azure-pipelines.yml", doc).passed is True


class TestADO001TaskPinning:
    def test_exploit_example_strong_check(self):
        # Both fragments parse and round-trip correctly.
        # Vulnerable uses AzureCLI@2 (floating major); Safe uses AzureCLI@2.245.0.
        vuln, safe = ado001.RULE.exploit_example.split("\n\n", 1)
        assert ado001.check("azure-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert ado001.check("azure-pipelines.yml", yaml.safe_load(safe)).passed is True

    def test_at2x_fires(self):
        # ``@2.x`` does NOT satisfy TASK_PIN_RE (requires a digit after the
        # first dot). Documenting this explicitly because the old Safe comment
        # suggested ``@2.x`` was acceptable for first-party tasks -- it is not.
        doc = yaml.safe_load(
            "steps:\n"
            "  - task: AzureCLI@2.x\n"
            "    inputs:\n"
            "      azureSubscription: prod-sub\n"
            "      scriptType: bash\n"
            "      scriptLocation: inlineScript\n"
            "      inlineScript: az deploy ...\n"
        )
        assert ado001.check("azure-pipelines.yml", doc).passed is False

    def test_safe_comment_no_misleading_version(self):
        # The ``@2.x`` advice was removed from the Safe comment. Verify the
        # exploit_example string no longer contains that misleading fragment.
        assert "@2.x" not in ado001.RULE.exploit_example


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
