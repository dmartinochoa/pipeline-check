"""Per-rule tests for GHA-086 (wildcard branch trigger + environment binding).

The positive fixture is the scenario-25 workflow body from
``greylag-ci/cicd-goat`` (``scenarios/25-environment-branch-pattern-bypass``).
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA086WildcardBranchEnvironment:
    def test_fails_on_cicd_goat_scenario_25_body(self):
        # Body lifted verbatim from
        # cicd-goat/.github/workflows/scenario-25-environment-branch-pattern-bypass.yml.
        wf = """
        name: scenario-25-environment-branch-pattern-bypass
        on:
          push:
            branches: ['main*']
        permissions:
          contents: read
          id-token: write
        jobs:
          deploy:
            if: false
            runs-on: ubuntu-latest
            environment:
              name: production
              url: https://prod.example.com
            steps:
              - uses: actions/checkout@v4
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-086")
        assert not f.passed
        assert "'main*'" in f.description
        assert "deploy" in f.description

    def test_passes_on_exact_branch(self):
        wf = """
        on:
          push:
            branches: [main]
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        assert run_check(wf, "GHA-086").passed

    def test_passes_when_environment_absent(self):
        wf = """
        on:
          push:
            branches: ['feature/*']
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo build
        """
        assert run_check(wf, "GHA-086").passed

    def test_passes_when_no_push_filter(self):
        wf = """
        on:
          workflow_dispatch:
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        assert run_check(wf, "GHA-086").passed

    def test_fails_on_release_wildcard(self):
        wf = """
        on:
          push:
            branches: ['release/*']
        jobs:
          publish:
            runs-on: ubuntu-latest
            environment:
              name: production
            steps:
              - run: ./publish.sh
        """
        f = run_check(wf, "GHA-086")
        assert not f.passed
        assert "'release/*'" in f.description

    def test_fails_on_star_pattern(self):
        wf = """
        on:
          push:
            branches: ['*']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: staging
            steps:
              - run: echo deploy
        """
        assert not run_check(wf, "GHA-086").passed

    def test_fails_on_question_mark_wildcard(self):
        wf = """
        on:
          push:
            branches: ['v?']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        assert not run_check(wf, "GHA-086").passed

    def test_fails_on_charset_wildcard(self):
        wf = """
        on:
          push:
            branches: ['main[abc]']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        assert not run_check(wf, "GHA-086").passed

    def test_mixed_patterns_one_wildcard_fires(self):
        # At least one wildcard pattern is enough to fire, since the
        # wildcard branch introduces the bypass surface even when the
        # exact patterns are also listed.
        wf = """
        on:
          push:
            branches: [main, 'release/*']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-086")
        assert not f.passed
        assert "'release/*'" in f.description

    def test_environment_as_long_form_dict(self):
        wf = """
        on:
          push:
            branches: ['main*']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment:
              name: production
              url: https://prod.example.com
            steps:
              - run: ./deploy.sh
        """
        f = run_check(wf, "GHA-086")
        assert not f.passed
        assert "deploy" in f.description

    def test_branches_ignore_not_flagged(self):
        wf = """
        on:
          push:
            branches-ignore: ['main*']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        # branches-ignore restricts triggers rather than expanding them.
        assert run_check(wf, "GHA-086").passed

    def test_negation_pattern_with_no_wildcard_stripped(self):
        # ``!main`` is an exact-branch exclusion. Not a wildcard.
        # (Real workflows would pair this with an include pattern;
        # we just verify the negation strip doesn't false-positive.)
        wf = """
        on:
          push:
            branches: ['!main']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        assert run_check(wf, "GHA-086").passed

    def test_tags_filter_not_flagged(self):
        wf = """
        on:
          push:
            tags: ['v*']
        jobs:
          deploy:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: ./deploy.sh
        """
        # Tag creation is generally a higher-privilege operation than
        # branch creation, so wildcard tags don't carry the same
        # bypass shape.
        assert run_check(wf, "GHA-086").passed

    def test_multiple_environment_jobs_all_reported(self):
        wf = """
        on:
          push:
            branches: ['main*']
        jobs:
          deploy-prod:
            runs-on: ubuntu-latest
            environment: production
            steps: [{run: ./deploy.sh}]
          deploy-stage:
            runs-on: ubuntu-latest
            environment: staging
            steps: [{run: ./deploy.sh}]
        """
        f = run_check(wf, "GHA-086")
        assert not f.passed
        assert "2 job(s)" in f.description
        assert "deploy-prod" in f.description
        assert "deploy-stage" in f.description
