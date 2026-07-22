"""Regression tests from the rule audit (Buildkite FN / example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.buildkite.rules import (
    bk005_docker_privileged as bk005,
)
from pipeline_check.core.checks.buildkite.rules import (
    bk009_signing as bk009,
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


# ── TAINT-005 verify-stale ─────────────────────────────────────────────
#
# Batch 2 added BUILDKITE_PULL_REQUEST_TITLE to the tainted-var set.
# The test in TestTAINT005MetadataTaint above (line ~20) already pins
# this behavior.  Confirming STALE: the existing test fires correctly.


# ── BK-009 batch-5 FN: buildkite-agent artifact upload not recognized ──


class TestBK009BuildkiteArtifactUpload:
    """BK-009: ``buildkite-agent artifact upload`` is the canonical
    Buildkite mechanism for publishing build artifacts. It was absent
    from _ARTIFACT_TOKENS, so a pipeline that uploads via this command
    (without also running docker build/push) was not recognized as
    artifact-producing and BK-009 silently passed."""

    def test_unsigned_artifact_upload_fires_bk009(self):
        # A pipeline that only uploads via buildkite-agent artifact upload
        # and has no signing step must now fire BK-009.
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: |\n"
            "      make build\n"
            "      buildkite-agent artifact upload dist/*.tar.gz\n"
        )
        assert bk009.check("pipeline.yml", doc).passed is False, (
            "BK-009 must fire when buildkite-agent artifact upload is present "
            "but no signing tool is invoked"
        )

    def test_signed_artifact_upload_passes_bk009(self):
        # A pipeline that uploads an artifact AND signs it must pass BK-009.
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: |\n"
            "      make build\n"
            "      cosign sign --yes dist/app\n"
            "      buildkite-agent artifact upload dist/*.tar.gz\n"
        )
        assert bk009.check("pipeline.yml", doc).passed is True, (
            "BK-009 must pass when the pipeline both uploads and signs"
        )

    def test_no_artifact_step_still_skips_bk009(self):
        # A pipeline with no artifact-producing step must still skip BK-009
        # (no false positive on lint/test-only pipelines).
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: pytest tests/\n"
        )
        assert bk009.check("pipeline.yml", doc).passed is True, (
            "BK-009 must pass (no artifact) on a test-only pipeline"
        )


class TestAudit202607LowBuildkiteC2:
    """2026-07 audit LOW findings (buildkite_c2 chunk)."""

    @staticmethod
    def run_check(text, cid):
        from tests.buildkite.conftest import run_check
        return run_check(text, cid)

    def test_bk016_shell_idiom_in_label_not_flagged(self):
        label = (
            "steps:\n"
            "  - label: \"Run eval $CONFIG sanity checks\"\n"
            "    command: make test\n"
        )
        assert self.run_check(label, "BK-016").passed is True
        cmd = "steps:\n  - command: eval \"$USER_INPUT\"\n"
        assert self.run_check(cmd, "BK-016").passed is False

    def test_bk017_env_dash_i_clean_env_not_a_dump(self):
        clean = "steps:\n  - command: \"env -i ./clean-build.sh\"\n"
        assert self.run_check(clean, "BK-017").passed is True

    def test_taint005_shared_label_does_not_collapse_steps(self):
        wf = (
            "steps:\n"
            "  - label: build\n"
            "    command: 'buildkite-agent meta-data set \"t\" "
            "\"$BUILDKITE_PULL_REQUEST_TITLE\"'\n"
            "  - label: build\n"
            "    command: 'buildkite-agent meta-data get t'\n"
        )
        assert self.run_check(wf, "TAINT-005").passed is False


class TestAudit202607LowBuildkiteC1:
    """2026-07 audit LOW findings (buildkite_c1 chunk)."""

    @staticmethod
    def run_check(text, cid):
        from tests.buildkite.conftest import run_check
        return run_check(text, cid)

    def test_bk015_pull_request_title_taints_agents_queue(self):
        # BK-015 advertised $BUILDKITE_PULL_REQUEST_* but its tainted set
        # omitted BUILDKITE_PULL_REQUEST_TITLE (attacker-controllable), so a
        # queue interpolated from it slipped through.
        wf = (
            "steps:\n"
            "  - agents: {queue: \"q-$BUILDKITE_PULL_REQUEST_TITLE\"}\n"
            "    command: make\n"
        )
        assert self.run_check(wf, "BK-015").passed is False
