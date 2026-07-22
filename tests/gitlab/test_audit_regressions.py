"""Regression tests from the rule audit (GitLab CI fixes)."""
from __future__ import annotations

from .conftest import run_check


class TestGL022PipUpgradeShortForm:
    """A5: the ``pip install -U`` short form was invisible (case-sensitive
    ``-U`` matched against a lowercased blob)."""

    def test_pip_dash_u_fires(self):
        cfg = (
            "build:\n"
            "  script:\n"
            "    - pip install -U requests\n"
        )
        assert run_check(cfg, "GL-022").passed is False

    def test_exempt_tooling_upgrade_still_passes(self):
        cfg = (
            "build:\n"
            "  script:\n"
            "    - pip install -U pip\n"
        )
        assert run_check(cfg, "GL-022").passed is True


class TestAudit202607LowGitlab:
    """2026-07 audit LOW findings on the GitLab rules."""

    def test_gl002_two_hop_variable_taint(self):
        cfg = (
            "build:\n"
            "  variables: { A: $CI_COMMIT_MESSAGE, B: $A }\n"
            "  script: [echo $B]\n"
        )
        assert run_check(cfg, "GL-002").passed is False

    def test_gl004_mixed_manual_and_catch_all_is_ungated(self):
        mixed = (
            "deploy_prod:\n"
            "  stage: deploy\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == \"main\"'\n"
            "      when: manual\n"
            "    - if: '$CI_COMMIT_BRANCH'\n"
            "  script: [./deploy.sh]\n"
        )
        assert run_check(mixed, "GL-004").passed is False
        fully = (
            "deploy_prod:\n"
            "  stage: deploy\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == \"main\"'\n"
            "      when: manual\n"
            "  script: [./deploy.sh]\n"
        )
        assert run_check(fully, "GL-004").passed is True

    def test_gl010_verification_must_be_in_the_ingesting_job(self):
        unrelated = (
            "deploy:\n"
            "  needs: [{project: vendor/build, job: package, ref: main, "
            "artifacts: true}]\n"
            "  script: [./build-output/release]\n"
            "other_job:\n"
            "  script: [\"cosign verify myimage:1.0\"]\n"
        )
        assert run_check(unrelated, "GL-010").passed is False
        same = (
            "deploy:\n"
            "  needs: [{project: vendor/build, job: package, ref: main, "
            "artifacts: true}]\n"
            "  script: [\"cosign verify ./build-output/release\", "
            "\"./build-output/release\"]\n"
        )
        assert run_check(same, "GL-010").passed is True

    def test_gl013_dict_wrapped_and_secret_export(self):
        dict_wrapped = (
            "variables:\n"
            "  AWS_ACCESS_KEY_ID: { value: \"AKIAZ3MHALF2TESTHIJK\", "
            "description: prod key }\n"
        )
        assert run_check(dict_wrapped, "GL-013").passed is False
        secret_export = (
            "job:\n"
            "  script: [\"export AWS_SECRET_ACCESS_KEY="
            "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"]\n"
        )
        assert run_check(secret_export, "GL-013").passed is False
        var_ref = (
            "job:\n"
            "  script: [\"export AWS_SECRET_ACCESS_KEY=$MY_SECRET\"]\n"
        )
        assert run_check(var_ref, "GL-013").passed is True


class TestAudit202607LowGitlabC2:
    """2026-07 audit LOW findings (gitlab_c2 chunk)."""

    def test_gl017_docker_privileged_does_not_span_lines(self):
        fp = (
            "job:\n"
            "  script:\n"
            "    - echo \"note -- do not pass --privileged here\"\n"
            "    - docker run --rm builder make dist\n"
        )
        assert run_check(fp, "GL-017").passed is True
        real = (
            "job:\n"
            "  script:\n"
            "    - docker run --privileged builder make dist\n"
        )
        assert run_check(real, "GL-017").passed is False

    def test_gl021_bare_yarn_is_an_install(self):
        bare = "job:\n  script: [yarn, yarn build]\n"
        assert run_check(bare, "GL-021").passed is False
        frozen = "job:\n  script: [yarn install --frozen-lockfile]\n"
        assert run_check(frozen, "GL-021").passed is True

    def test_gl028_bare_major_service_tag_flagged(self):
        major = "job:\n  services: [postgres:16]\n  script: [make]\n"
        assert run_check(major, "GL-028").passed is False
        minor = "job:\n  services: [postgres:16.2]\n  script: [make]\n"
        assert run_check(minor, "GL-028").passed is True


class TestAudit202607LowGitlabC4:
    """2026-07 audit LOW findings (gitlab_c4 chunk)."""

    def test_gl046_movable_revision_is_not_a_pin(self):
        from pipeline_check.core.checks._primitives.model_ref import _REVISION_RE
        assert not _REVISION_RE.search("revision='main'")
        assert _REVISION_RE.search("revision='abc1234def'")

    def test_gl048_prefix_taint_does_not_match_sanitized_name(self):
        clean = (
            "job:\n"
            "  variables: {TITLE: $CI_MERGE_REQUEST_TITLE, TITLE_SAFE: ok}\n"
            "  script: ['claude -p \"triage $TITLE_SAFE\"']\n"
        )
        assert run_check(clean, "GL-048").passed is True
        tainted = (
            "job:\n"
            "  variables: {TITLE: $CI_MERGE_REQUEST_TITLE}\n"
            "  script: ['claude -p \"triage $TITLE\"']\n"
        )
        assert run_check(tainted, "GL-048").passed is False

    def test_taint004_printf_dotenv_write(self):
        wf = (
            "extract:\n"
            "  script: ['printf \"TITLE=%s\" \"$CI_COMMIT_TITLE\" > taint.env']\n"
            "  artifacts: {reports: {dotenv: taint.env}}\n"
            "consume:\n"
            "  needs: [extract]\n"
            "  script: ['echo $TITLE']\n"
        )
        assert run_check(wf, "TAINT-004").passed is False


class TestAudit202607LowGitlabC3:
    """2026-07 audit LOW findings (gitlab_c3 chunk)."""

    def test_gl036_set_check_expansion_not_a_leak(self):
        # ``${TOKEN:+is set}`` prints "is set", never the secret value.
        safe = (
            "deploy:\n"
            "  script:\n"
            "    - echo \"token ${DEPLOY_TOKEN:+is set}\"\n"
        )
        assert run_check(safe, "GL-036").passed is True
        # ``${TOKEN:-default}`` prints the value when set -> still a leak.
        leak = (
            "deploy:\n"
            "  script:\n"
            "    - echo \"token ${DEPLOY_TOKEN:-none}\"\n"
        )
        assert run_check(leak, "GL-036").passed is False

    def test_gl043_non_false_disabled_value_fires(self):
        # Legacy templates disable on any non-empty value.
        weird = "variables: {SAST_DISABLED: \"if-you-say-so\"}\n"
        assert run_check(weird, "GL-043").passed is False
        # an explicit falsy value keeps the scanner enabled
        enabled = "variables: {SAST_DISABLED: \"false\"}\n"
        assert run_check(enabled, "GL-043").passed is True
