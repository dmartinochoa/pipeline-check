"""TKN-018. Dangerous shell idiom (eval, sh -c variable, backtick exec)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


def _task(script: str) -> str:
    return (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: build}\n"
        "spec:\n"
        "  steps:\n"
        "    - name: run\n"
        "      image: alpine:3\n"
        "      script: |\n"
        f"        {script}\n"
    )


class TestTKN018ShellEval:
    def test_metadata(self):
        f = run_check(_task("make build"), "TKN-018")
        assert f.check_id == "TKN-018"
        assert f.severity is Severity.HIGH

    def test_fails_on_eval_variable(self):
        f = run_check(_task('eval "$BUILD_CMD"'), "TKN-018")
        assert not f.passed

    def test_passes_on_ssh_agent_bootstrap(self):
        # eval of a literal subcommand's output is intentionally allowed.
        f = run_check(_task('eval "$(ssh-agent -s)"'), "TKN-018")
        assert f.passed

    def test_passes_on_direct_command(self):
        f = run_check(_task('./scripts/dispatch.sh "$BUILD_CMD"'), "TKN-018")
        assert f.passed
