"""ARGO-019. Dangerous shell idiom (eval, sh -c variable, backtick exec)."""
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


class TestARGO019ShellEval:
    def test_metadata(self):
        f = run_check(_wf("make build"), "ARGO-019")
        assert f.check_id == "ARGO-019"
        assert f.severity is Severity.HIGH

    def test_fails_on_eval_variable(self):
        f = run_check(_wf('eval "$BUILD_CMD"'), "ARGO-019")
        assert not f.passed

    def test_passes_on_ssh_agent_bootstrap(self):
        f = run_check(_wf('eval "$(ssh-agent -s)"'), "ARGO-019")
        assert f.passed

    def test_passes_on_direct_command(self):
        f = run_check(_wf('./scripts/dispatch.sh "$BUILD_CMD"'), "ARGO-019")
        assert f.passed

    def test_fails_on_eval_in_container_command(self):
        # ``eval`` placed directly in ``command`` was never scanned
        # (Part-C FN: only source + args were read).
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
            '        command: ["sh", "-c", "eval \\"$BUILD_CMD\\""]\n'
        )
        f = run_check(wf, "ARGO-019")
        assert not f.passed
