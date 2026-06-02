"""Regression tests from the rule audit (Azure Pipelines fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks._primitives import tls_bypass
from pipeline_check.core.checks.azure.rules import ado013_self_hosted_ephemeral as ado013
from pipeline_check.core.checks.base import DOCKER_INSECURE_RE, has_dep_update

from .conftest import run_check


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
