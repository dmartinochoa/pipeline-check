"""Per-rule tests for GHA-070 (ssh-keyscan / disabled host-key check TOFU)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA070SshKeyscanTOFU:
    def test_fails_on_ssh_keyscan_append(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  mkdir -p ~/.ssh
                  ssh-keyscan github.com >> ~/.ssh/known_hosts
                  git fetch git@github.com:org/repo.git
        """
        f = run_check(wf, "GHA-070")
        assert not f.passed
        assert "ssh-keyscan" in f.description

    def test_fails_on_strict_host_key_checking_no(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ssh -o StrictHostKeyChecking=no user@host ls
        """
        assert not run_check(wf, "GHA-070").passed

    def test_fails_on_strict_accept_new(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ssh -o StrictHostKeyChecking=accept-new user@host ls
        """
        assert not run_check(wf, "GHA-070").passed

    def test_fails_on_user_known_hosts_file_devnull(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ssh -o UserKnownHostsFile=/dev/null user@host ls
        """
        assert not run_check(wf, "GHA-070").passed

    def test_fails_on_rsync_with_strict_no(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: rsync -e "ssh -o StrictHostKeyChecking=no" -avz . user@host:/srv/
        """
        assert not run_check(wf, "GHA-070").passed

    def test_passes_on_pinned_known_hosts(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  mkdir -p ~/.ssh
                  cp .github/ssh/github_known_hosts ~/.ssh/known_hosts
                  chmod 600 ~/.ssh/known_hosts
                  git fetch git@github.com:org/repo.git
        """
        assert run_check(wf, "GHA-070").passed

    def test_passes_on_default_ssh(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: ssh user@host ls
        """
        assert run_check(wf, "GHA-070").passed

    def test_fails_on_scp_with_strict_no(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: scp -o StrictHostKeyChecking=no file user@host:/srv/file
        """
        assert not run_check(wf, "GHA-070").passed

    def test_step_index_in_description(self):
        wf = """
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: echo build
              - run: ssh-keyscan github.com >> ~/.ssh/known_hosts
        """
        f = run_check(wf, "GHA-070")
        assert not f.passed
        assert "deploy[1]" in f.description
