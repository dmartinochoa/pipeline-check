"""Regression tests from the rule audit (Azure Pipelines fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks._primitives import tls_bypass
from pipeline_check.core.checks.azure.rules import ado001_task_pinning as ado001
from pipeline_check.core.checks.azure.rules import ado002_script_injection as ado002
from pipeline_check.core.checks.azure.rules import ado003_literal_secrets as ado003
from pipeline_check.core.checks.azure.rules import ado013_self_hosted_ephemeral as ado013
from pipeline_check.core.checks.azure.rules import ado027_shell_eval as ado027
from pipeline_check.core.checks.azure.rules import ado030_pool_injection as ado030
from pipeline_check.core.checks.base import DOCKER_INSECURE_RE, Severity, has_dep_update

from .conftest import run_check


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


# ── ADO-017 batch-5 FN: --network=host / --network host missed ──────────


class TestADO017NetworkLongForm:
    """DOCKER_INSECURE_RE must catch ``--network=host`` and
    ``--network host`` (Docker canonical long form), not only the
    abbreviated ``--net=host`` / ``--net host`` forms."""

    def test_network_equals_host_fires(self):
        # Previously missed: ``--network=host`` long form with ``=``.
        assert DOCKER_INSECURE_RE.search(
            "docker run --network=host myimage"
        ), "DOCKER_INSECURE_RE missed --network=host"

    def test_network_space_host_fires(self):
        # Previously missed: ``--network host`` long form with a space.
        assert DOCKER_INSECURE_RE.search(
            "docker run --network host myimage"
        ), "DOCKER_INSECURE_RE missed --network host"

    def test_net_equals_host_still_fires(self):
        # Existing true-positive must not regress.
        assert DOCKER_INSECURE_RE.search("docker run --net=host myimage")

    def test_net_space_host_still_fires(self):
        # Existing true-positive must not regress.
        assert DOCKER_INSECURE_RE.search("docker run --net host myimage")

    def test_benign_docker_run_does_not_fire(self):
        # A plain ``docker run`` without dangerous flags must not fire.
        assert not DOCKER_INSECURE_RE.search("docker run --rm myapp")

    def test_pipeline_network_host_fires_ado017(self):
        # End-to-end: the rule fires when a step uses ``--network=host``.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker run --network=host builder ./test.sh
        """
        f = run_check(cfg, "ADO-017")
        assert not f.passed, "ADO-017 should fail on --network=host"

    def test_pipeline_benign_passes_ado017(self):
        # End-to-end: a benign step does not fire.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker run --rm builder ./test.sh
        """
        f = run_check(cfg, "ADO-017")
        assert f.passed, "ADO-017 should pass with no insecure flags"


# ── ADO-022 batch-5 FN: mixed-line exemption suppresses real command ─────


class TestADO022MixedLineExemption:
    """When an exempt tooling upgrade and a real dep-update command share
    the same line, the rule must fire on the real command.  Previously
    the full-line exemption test suppressed the finding."""

    def test_mixed_line_fires(self):
        # Both an exempt ``pip install --upgrade pip`` and a real
        # ``npm update`` appear on the same line (e.g. a shell one-liner).
        # The exemption must be scoped to the matched segment, not the
        # whole line, so the real ``npm update`` still fires.
        blob = "pip install --upgrade pip && npm update"
        assert has_dep_update(blob), (
            "has_dep_update should fire when a real dep-update command "
            "appears alongside an exempt tooling upgrade on the same line"
        )

    def test_exempt_only_line_passes(self):
        # A line with only an exempt tooling upgrade must still pass.
        blob = "pip install --upgrade pip"
        assert not has_dep_update(blob), (
            "has_dep_update should not fire on a tooling-only upgrade"
        )

    def test_real_dep_update_alone_fires(self):
        # Existing true-positive: a bare dep-update command must fire.
        assert has_dep_update("npm update")

    def test_pipeline_mixed_line_fires_ado022(self):
        # End-to-end: a step that mixes exempt and real commands fires.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: pip install --upgrade pip && npm update
        """
        f = run_check(cfg, "ADO-022")
        assert not f.passed, (
            "ADO-022 should fail when a real dep-update command is "
            "present alongside an exempt tooling upgrade"
        )

    def test_pipeline_tooling_upgrade_only_passes_ado022(self):
        # End-to-end: a step with only an exempt tooling upgrade passes.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: pip install --upgrade pip
        """
        f = run_check(cfg, "ADO-022")
        assert f.passed, "ADO-022 should pass on a tooling-only upgrade"


# ── ADO-023 batch-5 FN: git -c http.sslVerify=false inline form ──────────


class TestADO023GitInlineSslVerify:
    """The tls_bypass primitive must catch the per-invocation inline form
    ``git -c http.sslVerify=false <cmd>`` in addition to the ``git config``
    subcommand form."""

    def test_git_inline_sslverify_fires(self):
        # Previously missed: ``git -c http.sslVerify=false clone ...``.
        hits = tls_bypass.scan("git -c http.sslVerify=false clone https://repo.example.com/r.git")
        assert hits, "tls_bypass missed git -c http.sslVerify=false"
        assert any(h.tool == "git" for h in hits)

    def test_git_inline_sslverify_kind_tag(self):
        hits = tls_bypass.scan("git -c http.sslVerify=false fetch origin")
        assert any(h.kind == "git-inline-sslverify-false" for h in hits)

    def test_git_config_form_still_fires(self):
        # Existing true-positive must not regress.
        hits = tls_bypass.scan("git config --global http.sslVerify false")
        assert hits and any(h.tool == "git" for h in hits)

    def test_normal_git_clone_does_not_fire(self):
        # A plain ``git clone`` without any TLS bypass must not fire.
        hits = tls_bypass.scan("git clone https://repo.example.com/r.git")
        git_hits = [h for h in hits if h.tool == "git"]
        assert not git_hits, f"false positive: {git_hits}"

    def test_pipeline_git_inline_sslverify_fires_ado023(self):
        # End-to-end: ADO-023 fires when a step uses the inline form.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: git -c http.sslVerify=false clone https://repo.example.com/r.git
        """
        f = run_check(cfg, "ADO-023")
        assert not f.passed, "ADO-023 should fail on git -c http.sslVerify=false"

    def test_pipeline_normal_git_passes_ado023(self):
        # End-to-end: a normal git clone must pass.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: git clone https://repo.example.com/r.git
        """
        f = run_check(cfg, "ADO-023")
        assert f.passed, "ADO-023 should pass on a normal git clone"


# ── ADO-006 batch-5 FN: ``notation sign`` (space form) not recognized ───


class TestADO006NotationSignSpaceForm:
    """ADO-006: SIGN_TOKENS contained ``notation-sign`` (hyphenated) but
    not the real CLI invocation ``notation sign <ref>`` (space-separated).
    A pipeline that runs ``notation sign`` was incorrectly flagged as
    unsigned."""

    def test_notation_sign_space_passes_ado006(self):
        # ``notation sign`` (space-separated CLI form) must satisfy ADO-006.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
          - script: notation sign registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-006")
        assert f.passed, (
            "ADO-006 must pass when a step runs 'notation sign'"
        )

    def test_unsigned_artifact_pipeline_fires_ado006(self):
        # A pipeline that builds and pushes but has no signing must still fire.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-006")
        assert not f.passed, (
            "ADO-006 must fire when an artifact pipeline has no signing step"
        )

    def test_notation_hyphen_sign_still_passes_ado006(self):
        # The pre-existing ``notation-sign`` token (hyphenated) must still work.
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - task: Bash@3
            inputs:
              targetType: inline
              script: notation-sign registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-006")
        assert f.passed, (
            "ADO-006 must still pass on the hyphenated notation-sign form"
        )


class TestADO003SecretEscalation:
    """ADO-003: severity escalation used a bare ``"AWS" in offender``
    substring on the offender label, so a plain secret whose variable
    NAME merely contains "AWS" (e.g. ``AWS_DB_PASSWORD``) was escalated
    to CRITICAL though it is not an AWS access key. Also, a bare
    top-level ``variables:`` block was scanned twice (once as ``<top>``,
    once as the iter_jobs-yielded document)."""

    def test_aws_named_plain_secret_is_high_not_critical(self):
        # ``AWS_DB_PASSWORD`` holds a plain password, not an AKIA value;
        # it must be HIGH (a literal secret), not CRITICAL (an AWS key).
        doc = yaml.safe_load(
            "variables:\n"
            "  AWS_DB_PASSWORD: hunter2\n"
            "steps:\n"
            "  - script: make\n"
        )
        f = ado003.check("azure-pipelines.yml", doc)
        assert f.passed is False
        assert f.severity is Severity.HIGH

    def test_real_aws_key_value_still_critical(self):
        # A genuine AKIA-shaped value must still escalate to CRITICAL.
        doc = yaml.safe_load(
            "variables:\n"
            "  CREDS: AKIAZ3MHALF2TESTHIJK\n"
            "steps:\n"
            "  - script: make\n"
        )
        f = ado003.check("azure-pipelines.yml", doc)
        assert f.passed is False
        assert f.severity is Severity.CRITICAL

    def test_top_level_variables_scanned_once(self):
        # The bare top-level ``steps:`` shape makes iter_jobs yield the
        # document itself; its ``variables:`` must be counted once.
        doc = yaml.safe_load(
            "variables:\n"
            "  DB_PASSWORD: hunter2\n"
            "steps:\n"
            "  - script: make\n"
        )
        f = ado003.check("azure-pipelines.yml", doc)
        assert f.passed is False
        assert "1 variable(s)" in f.description
        assert f.description.count("DB_PASSWORD") == 1
