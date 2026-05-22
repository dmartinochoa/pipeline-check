"""Per-rule tests for GHA-063 (spoofable bot-actor if-predicate)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA063BotConditions:
    def test_fails_on_actor_eq_dependabot(self):
        wf = """
        on: pull_request
        jobs:
          auto-merge:
            if: ${{ github.actor == 'dependabot[bot]' }}
            runs-on: ubuntu-latest
            permissions: { contents: write }
            steps:
              - run: gh pr merge --auto --squash "${{ github.event.pull_request.number }}"
        """
        f = run_check(wf, "GHA-063")
        assert not f.passed
        assert "dependabot[bot]" in f.description

    def test_fails_on_triggering_actor(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: ${{ github.triggering_actor == 'renovate[bot]' }}
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-063").passed

    def test_fails_on_sender_login(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: github.event.sender.login == 'github-actions[bot]'
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-063").passed

    def test_fails_on_step_level_if(self):
        wf = """
        on: pull_request
        jobs:
          x:
            runs-on: ubuntu-latest
            steps:
              - if: ${{ github.actor == 'dependabot[bot]' }}
                run: echo bot
        """
        f = run_check(wf, "GHA-063")
        assert not f.passed
        assert "steps[0]" in f.description

    def test_fails_on_negation(self):
        wf = """
        on: pull_request
        jobs:
          human-only:
            if: ${{ github.actor != 'dependabot[bot]' }}
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-063").passed

    def test_fails_on_contains_actor_bot(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: contains(github.actor, 'bot')
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-063").passed

    def test_fails_on_ends_with_bracket_bot(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: endsWith(github.actor, '[bot]')
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-063").passed

    def test_passes_on_user_type_pair(self):
        wf = """
        on: pull_request
        jobs:
          auto-merge:
            if: |
              github.event.pull_request.user.type == 'Bot' &&
              github.event.pull_request.user.login == 'dependabot[bot]'
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-063").passed

    def test_passes_when_no_if(self):
        wf = """
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo
        """
        assert run_check(wf, "GHA-063").passed

    def test_passes_on_unrelated_predicate(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: github.event.action == 'opened'
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-063").passed

    def test_passes_on_codeowner_check(self):
        wf = """
        on: pull_request
        jobs:
          x:
            if: github.event.pull_request.author_association == 'OWNER'
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-063").passed
