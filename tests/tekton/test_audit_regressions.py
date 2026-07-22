"""Regression tests from the 2026-07 rule audit (Tekton false negatives)."""
from __future__ import annotations

from .conftest import run_check


def test_tkn015_bracket_notation_param_reference():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: t}\n"
        "spec:\n"
        "  steps:\n"
        "    - name: s\n"
        "      image: alpine@sha256:abc\n"
        "      workspaces: [{name: ws, subPath: \"$(params['target'])\"}]\n"
    )
    assert run_check(doc, "TKN-015").passed is False


def test_tkn016_inline_pipeline_spec_task_ref():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: PipelineRun\n"
        "metadata: {name: pr}\n"
        "spec:\n"
        "  pipelineSpec:\n"
        "    tasks:\n"
        "      - name: build\n"
        "        taskRef: {resolver: git, params: [{name: revision, "
        "value: main}]}\n"
    )
    assert run_check(doc, "TKN-016").passed is False


def test_tkn017_exec_form_log_leak():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: t}\n"
        "spec:\n"
        "  steps:\n"
        "    - name: s\n"
        "      image: alpine@sha256:abc\n"
        "      command: [\"echo\"]\n"
        "      args: [\"$PASSWORD\"]\n"
    )
    assert run_check(doc, "TKN-017").passed is False


def test_tkn018_exec_form_shell_eval():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: t}\n"
        "spec:\n"
        "  steps:\n"
        "    - name: s\n"
        "      image: alpine@sha256:abc\n"
        "      command: [\"sh\", \"-c\"]\n"
        "      args: [\"eval \\\"$USERINPUT\\\"\"]\n"
    )
    assert run_check(doc, "TKN-018").passed is False


def test_tkn013_nonroot_uid_sidecar_not_flagged():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata: {name: t}\n"
        "spec:\n"
        "  sidecars:\n"
        "    - name: s\n"
        "      image: alpine@sha256:abc\n"
        "      securityContext: {runAsUser: 1000, "
        "allowPrivilegeEscalation: false, privileged: false}\n"
        "  steps:\n"
        "    - name: st\n"
        "      image: alpine@sha256:abc\n"
        "      securityContext: {runAsNonRoot: true, "
        "allowPrivilegeEscalation: false}\n"
        "      script: echo hi\n"
    )
    assert run_check(doc, "TKN-013").passed is True


def test_tkn005_literal_secret_in_run_param_value():
    doc = (
        "apiVersion: tekton.dev/v1\n"
        "kind: PipelineRun\n"
        "metadata: {name: pr}\n"
        "spec:\n"
        "  params:\n"
        "    - name: AWS_ACCESS_KEY_ID\n"
        "      value: \"AKIAZ3MHALF2TESTHIJK\"\n"
    )
    assert run_check(doc, "TKN-005").passed is False


def test_tkn006_zero_timeout_is_no_timeout():
    zero = (
        "apiVersion: tekton.dev/v1\n"
        "kind: PipelineRun\n"
        "metadata: {name: pr}\n"
        "spec:\n"
        "  timeouts: {pipeline: \"0\"}\n"
        "  pipelineRef: {name: p}\n"
    )
    assert run_check(zero, "TKN-006").passed is False
    real = zero.replace('"0"', '"1h0m0s"')
    assert run_check(real, "TKN-006").passed is True
