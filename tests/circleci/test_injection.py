"""Per-rule tests for CircleCI shell-injection family rules:
CC-002 (run command interpolating attacker-controllable env var),
CC-027 (dangerous shell idiom — eval, ``sh -c "$VAR"``, backtick exec).

Both rules guard against shell-injection escape paths in
``run:`` step commands.
"""
from __future__ import annotations

from .conftest import run_check

# ── CC-002 untrusted env var in run ─────────────────────────────────


class TestCC002ScriptInjection:
    def test_fails_on_circle_branch_in_run(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: echo "Building $CIRCLE_BRANCH"
        """
        f = run_check(cfg, "CC-002")
        assert not f.passed

    def test_fails_on_circle_tag_in_run(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: deploy.sh "$CIRCLE_TAG"
        """
        f = run_check(cfg, "CC-002")
        assert not f.passed

    def test_fails_on_pipeline_git_branch_interpolation(self):
        # Native ``<< pipeline.git.branch >>`` splices the attacker-named
        # ref into the command at config-compile time (no shell env var).
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: echo "Building << pipeline.git.branch >>"
        """
        f = run_check(cfg, "CC-002")
        assert not f.passed

    def test_passes_on_pipeline_parameters_interpolation(self):
        # ``<< pipeline.parameters.* >>`` is typed and workflow-set: the
        # documented safe alternative, must not fire.
        cfg = """
        version: 2.1
        parameters:
          deploy_branch:
            type: string
            default: main
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: echo "Building << pipeline.parameters.deploy_branch >>"
        """
        f = run_check(cfg, "CC-002")
        assert f.passed

    def test_passes_when_no_untrusted_var(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make test
        """
        f = run_check(cfg, "CC-002")
        assert f.passed


# ── CC-027 dangerous shell idiom ────────────────────────────────────


class TestCC027ShellEval:
    def test_fails_on_eval_of_variable(self):
        cfg = """
        version: 2.1
        jobs:
          run:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: eval "$BUILD_CMD"
        """
        f = run_check(cfg, "CC-027")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        cfg = """
        version: 2.1
        jobs:
          run:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: sh -c "$USER_CMD"
        """
        f = run_check(cfg, "CC-027")
        assert not f.passed

    def test_passes_when_clean(self):
        cfg = """
        version: 2.1
        jobs:
          run:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: make test
        """
        f = run_check(cfg, "CC-027")
        assert f.passed
