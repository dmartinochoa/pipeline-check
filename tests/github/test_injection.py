"""Per-rule tests for GitHub Actions shell-injection family rules:
GHA-028 (dangerous shell idiom — eval, ``sh -c "$VAR"``, backtick exec).

Complements GHA-003 (script injection from PR-context interpolation)
which is covered in ``test_workflows.py``. GHA-028 fires regardless of
where the variable's value comes from; the idiom itself is the
problem.
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-028 dangerous shell idiom ───────────────────────────────────


class TestGHA028ShellEval:
    def test_fails_on_eval_of_variable(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: eval "$BUILD_CMD"
        """
        f = run_check(wf, "GHA-028")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: sh -c "$USER_CMD"
        """
        f = run_check(wf, "GHA-028")
        assert not f.passed

    def test_passes_when_clean(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-028")
        assert f.passed
