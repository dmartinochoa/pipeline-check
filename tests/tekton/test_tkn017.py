"""TKN-017. Secret-named variable echoed to the step log."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


def _task(script: str) -> str:
    return (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: deploy}\n"
        "spec:\n"
        "  steps:\n"
        "    - name: run\n"
        "      image: alpine:3\n"
        "      script: |\n"
        f"        {script}\n"
    )


class TestTKN017LogLeak:
    def test_metadata(self):
        f = run_check(_task("make build"), "TKN-017")
        assert f.check_id == "TKN-017"
        assert f.severity is Severity.HIGH

    def test_fails_on_echo_secret_named_var(self):
        f = run_check(
            _task('echo "token is $AWS_SECRET_ACCESS_KEY"'), "TKN-017",
        )
        assert not f.passed

    def test_fails_on_printenv_dump(self):
        f = run_check(_task("printenv"), "TKN-017")
        assert not f.passed

    def test_passes_on_safe_existence_check(self):
        f = run_check(
            _task('[ -n "$TOKEN" ] && echo set || echo unset'), "TKN-017",
        )
        assert f.passed
