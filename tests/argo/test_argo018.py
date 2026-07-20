"""ARGO-018. Secret-named variable echoed to the template log."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


def _wf(source: str) -> str:
    return (
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: {name: w}\n"
        "spec:\n"
        "  entrypoint: main\n"
        "  templates:\n"
        "    - name: main\n"
        "      script:\n"
        "        image: alpine:3\n"
        "        command: [bash]\n"
        "        source: |\n"
        f"          {source}\n"
    )


class TestARGO018LogLeak:
    def test_metadata(self):
        f = run_check(_wf("make build"), "ARGO-018")
        assert f.check_id == "ARGO-018"
        assert f.severity is Severity.HIGH

    def test_fails_on_echo_secret_named_var(self):
        f = run_check(_wf('echo "token is $AWS_SECRET_ACCESS_KEY"'), "ARGO-018")
        assert not f.passed

    def test_fails_on_printenv_dump(self):
        f = run_check(_wf("printenv"), "ARGO-018")
        assert not f.passed

    def test_passes_on_safe_existence_check(self):
        f = run_check(_wf('[ -n "$TOKEN" ] && echo set || echo unset'), "ARGO-018")
        assert f.passed

    def test_fails_on_leak_in_container_command(self):
        # ``command: ["sh","-c","<script>"]`` puts the shell body in
        # ``command``, which was never scanned (Part-C FN).
        wf = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  entrypoint: main\n"
            "  templates:\n"
            "    - name: main\n"
            "      container:\n"
            "        image: alpine:3\n"
            '        command: ["sh", "-c", "echo token is $AWS_SECRET_ACCESS_KEY"]\n'
        )
        f = run_check(wf, "ARGO-018")
        assert not f.passed
