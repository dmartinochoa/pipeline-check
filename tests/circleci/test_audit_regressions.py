"""Regression tests from the rule audit (CircleCI example fix)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.circleci.rules import cc008_literal_secrets as cc008
from pipeline_check.core.checks.circleci.rules import cc015_timeout as cc015
from pipeline_check.core.checks.circleci.rules import cc019_ssh_keys as cc019
from pipeline_check.core.checks.circleci.rules import cc024_slsa_provenance as cc024
from pipeline_check.core.checks.circleci.rules import cc031_oidc_trust as cc031


def _load(text: str) -> dict:
    return yaml.safe_load(text)


class TestCC008LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # The Vulnerable fragment must fire; it previously used vendor
        # example tokens (AKIAIOSFODNN7EXAMPLE) that find_secret_values
        # suppresses, so the documented example passed.
        vuln, safe = cc008.RULE.exploit_example.split("\n\n", 1)
        assert cc008.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc008.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


# ── CC-015 blob_lower fallback false-negative ────────────────────────


class TestCC015BlobFallbackFN:
    """CC-015: blob_lower() fallback matched the token as a string VALUE
    (e.g. a step name), never as a YAML key. Drop the fallback so a
    config that only MENTIONS the word in a name: field still fails.
    """

    def test_fires_when_token_only_in_step_name(self):
        # 'no_output_timeout' appears only as a step name value, not as
        # a run-step key. Previously the blob fallback swallowed this and
        # returned passed=True (false negative).
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          name: "remind team to set no_output_timeout"
          command: ./build.sh
""")
        assert cc015.check("cfg.yml", doc).passed is False

    def test_passes_with_real_run_step_timeout(self):
        # A genuine no_output_timeout: key on a run step must still pass.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          name: long build
          no_output_timeout: 20m
          command: ./build.sh
""")
        assert cc015.check("cfg.yml", doc).passed is True

    def test_fires_when_no_run_steps_at_all(self):
        # A job with only a checkout step and no run: block has no
        # timeout configured.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - checkout
""")
        assert cc015.check("cfg.yml", doc).passed is False


# ── CC-019 commands block and when:/unless: false-negatives ─────────


class TestCC019CommandsAndConditionalFN:
    """CC-019: bare add_ssh_keys inside reusable commands: or inside a
    when:/unless: conditional step group was previously missed.
    """

    def test_fires_bare_add_ssh_keys_in_commands_block(self):
        # A top-level commands: entry with a bare add_ssh_keys step must fire.
        doc = _load("""
version: 2.1
commands:
  setup_keys:
    steps:
      - add_ssh_keys
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - setup_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_fires_bare_add_ssh_keys_inside_when_group(self):
        # A bare add_ssh_keys nested under a when: conditional group must fire.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - when:
          condition: << parameters.deploy >>
          steps:
            - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_fires_bare_add_ssh_keys_inside_unless_group(self):
        # A bare add_ssh_keys nested under an unless: conditional group must fire.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - unless:
          condition: << parameters.skip_keys >>
          steps:
            - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_passes_with_fingerprints_in_commands_block(self):
        # A commands: entry that uses add_ssh_keys WITH fingerprints is safe.
        doc = _load("""
version: 2.1
commands:
  setup_keys:
    steps:
      - add_ssh_keys:
          fingerprints:
            - "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - setup_keys
""")
        assert cc019.check("cfg.yml", doc).passed is True

    def test_existing_bare_job_step_still_fires(self):
        # Regression: the original top-level job step path must still work.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False


# ── CC-031 underscore parameter forms false-negative ─────────────────


class TestCC031UnderscoreParamsFN:
    """CC-031: only hyphenated param names (role-arn) were in
    _OIDC_ROLE_PARAMS; the underscore forms (role_arn, oidc_role_arn)
    were silently ignored.
    """

    def test_fires_on_role_arn_underscore_no_gate(self):
        # role_arn (underscore) without branch filter or approval must fire.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role_arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False

    def test_fires_on_oidc_role_arn_underscore_no_gate(self):
        # oidc_role_arn (underscore) without a gate must fire.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          oidc_role_arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False

    def test_passes_on_role_arn_underscore_with_branch_filter(self):
        # role_arn with a branch filter is safe (same as hyphenated form).
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role_arn: arn:aws:iam::123456789012:role/prod-deploy
          filters:
            branches:
              only: main
""")
        assert cc031.check("cfg.yml", doc).passed is True

    def test_hyphenated_form_still_fires(self):
        # Existing hyphenated form (role-arn) must still fire without a gate.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role-arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False


# ── CC-024 batch-5 FN: circleci/attestation orb not in PROVENANCE_TOKENS ─


class TestCC024CircleCIAttestationOrb:
    """CC-024: the recommendation names the ``circleci/attestation`` orb
    as the canonical CircleCI SLSA provenance mechanism, but neither
    ``circleci/attestation`` nor ``attestation/attest`` was in
    PROVENANCE_TOKENS, so a config using that orb was incorrectly flagged
    as lacking provenance."""

    def test_circleci_attestation_orb_passes_cc024(self):
        # A config that uses the circleci/attestation orb must pass CC024.
        doc = _load("""
version: 2.1
orbs:
  attestation: circleci/attestation@0.0.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: |
            docker build -t registry.example.com/app:v1 .
            docker push registry.example.com/app:v1
      - attestation/attest:
          image-ref: registry.example.com/app:v1
          digest: sha256:abc123
workflows:
  main:
    jobs:
      - build
""")
        assert cc024.check(".circleci/config.yml", doc).passed is True, (
            "CC-024 must pass when the circleci/attestation orb is used"
        )

    def test_no_provenance_artifact_pipeline_fires_cc024(self):
        # A config that publishes but has no provenance step must still fire.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: |
            docker build -t registry.example.com/app:v1 .
            docker push registry.example.com/app:v1
workflows:
  main:
    jobs:
      - build
""")
        assert cc024.check(".circleci/config.yml", doc).passed is False, (
            "CC-024 must fire when an artifact config has no provenance step"
        )

    def test_no_artifact_config_skips_cc024(self):
        # A config with no artifact-producing step must skip CC-024 (no FP).
        doc = _load("""
version: 2.1
jobs:
  test:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: pytest tests/
workflows:
  main:
    jobs:
      - test
""")
        assert cc024.check(".circleci/config.yml", doc).passed is True, (
            "CC-024 must pass (no artifact) on a test-only config"
        )
