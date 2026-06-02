"""Regression tests from the rule audit (Buildkite FN / example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.buildkite.rules import (
    bk005_docker_privileged as bk005,
)
from pipeline_check.core.checks.buildkite.rules import (
    bk013_deploy_branch_filter as bk013,
)
from pipeline_check.core.checks.buildkite.rules import (
    taint005_metadata_taint as taint005,
)


def _halves(rule):
    """Split a RULE.exploit_example into (vulnerable_doc, safe_doc)."""
    vuln, safe = rule.exploit_example.split("\n\n", 1)
    return yaml.safe_load(vuln), yaml.safe_load(safe)


class TestTAINT005MetadataTaint:
    def test_pull_request_title_is_a_tainted_source(self):
        # BUILDKITE_PULL_REQUEST_TITLE is the documented canonical
        # injection source; it was missing from the tainted-var set.
        doc = yaml.safe_load(
            'steps:\n'
            '  - command: buildkite-agent meta-data set "t" "$BUILDKITE_PULL_REQUEST_TITLE"\n'
            '  - command: |\n'
            '      T=$(buildkite-agent meta-data get t)\n'
            '      echo $T\n'
        )
        assert taint005.check("pipeline.yml", doc).passed is False


class TestBK005DockerPrivileged:
    def test_privileged_docker_plugin_fires(self):
        # The danger can be expressed through the docker plugin config
        # (privileged: true / host socket mount), not only a command.
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: ./it.sh\n"
            "    plugins:\n"
            "      - docker#v5.10.0:\n"
            "          image: app\n"
            "          privileged: true\n"
        )
        assert bk005.check("pipeline.yml", doc).passed is False

    def test_docker_sock_mount_fires(self):
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: ./it.sh\n"
            "    plugins:\n"
            "      - docker#v5.10.0:\n"
            "          image: app\n"
            "          volumes:\n"
            "            - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        assert bk005.check("pipeline.yml", doc).passed is False

    def test_exploit_example_strong_check(self):
        vuln, safe = _halves(bk005.RULE)
        assert bk005.check("pipeline.yml", vuln).passed is False
        assert bk005.check("pipeline.yml", safe).passed is True


class TestBK013DeployBranchFilterFP:
    """BK-013 false-positive regression: mid-phrase 'release'/'promote' in
    a step label must not be treated as deploy intent when the step's
    command performs no deploy action."""

    def _doc(self, label: str, command: str) -> dict:
        return yaml.safe_load(
            f"steps:\n"
            f"  - label: \"{label}\"\n"
            f"    command: \"{command}\"\n"
        )

    # ── False-positive cases (safe inputs that must PASS) ──────────────

    def test_build_release_artifact_label_passes(self):
        # "release" appears mid-phrase; command is a pure build — no deploy.
        doc = self._doc("Build release artifact", "docker build -t app:latest .")
        assert bk013.check("pipeline.yml", doc).passed is True

    def test_generate_release_notes_label_passes(self):
        doc = self._doc("Generate release notes", "scripts/gen_notes.sh")
        assert bk013.check("pipeline.yml", doc).passed is True

    def test_mid_phrase_promote_label_passes(self):
        # "promote" mid-phrase (not leading), pure build command — no deploy.
        doc = self._doc("Check promotion eligibility", "scripts/check_promo.sh")
        assert bk013.check("pipeline.yml", doc).passed is True

    def test_build_and_release_artifacts_label_passes(self):
        doc = self._doc("Build and release artifacts", "make package")
        assert bk013.check("pipeline.yml", doc).passed is True

    # ── True-positive cases (genuine deploys that must FIRE) ───────────

    def test_leading_release_label_no_branches_fires(self):
        # "Release to production" — leading verb, no branches: filter.
        doc = self._doc("Release to production", "scripts/release.sh")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_leading_promote_label_no_branches_fires(self):
        # "Promote to staging" — leading verb, no branches: filter.
        doc = self._doc("Promote to staging", "scripts/promote.sh")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_emoji_leading_release_label_no_branches_fires(self):
        # Emoji prefix before "Release" is common in Buildkite labels.
        doc = self._doc(":rocket: Release to prod", "scripts/release.sh")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_deploy_label_no_branches_fires(self):
        # Unambiguous "deploy" in label still fires as before.
        doc = self._doc("Deploy production", "kubectl apply -f k8s/")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_build_label_but_deploy_command_fires(self):
        # Label has no deploy keyword, but command runs kubectl apply.
        doc = self._doc("Build release artifact", "kubectl apply -f k8s/")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_build_label_release_command_fires(self):
        # Command explicitly calls a release script — fires via command path.
        doc = self._doc("Build release artifact", "scripts/release.sh --env prod")
        assert bk013.check("pipeline.yml", doc).passed is False

    def test_leading_release_label_with_branches_passes(self):
        # Genuine deploy label + branches: filter = correctly passes.
        doc = yaml.safe_load(
            "steps:\n"
            "  - label: \"Release to production\"\n"
            "    branches: \"main\"\n"
            "    command: \"scripts/release.sh\"\n"
        )
        assert bk013.check("pipeline.yml", doc).passed is True
