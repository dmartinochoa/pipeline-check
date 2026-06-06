"""Source-location coverage for the aggregate Tekton rules.

These rules emit one Finding per check across the whole corpus and used to
set ``resource="tekton"`` with no ``Location`` (TKN-001 was the exception,
TKN-002/003 are backfilled from their ``job_anchors`` by the orchestrator).
They now attach one ``Location`` per offending document via
``doc_location``. Each rule is driven by a manifest crafted to trip it.
"""
from __future__ import annotations

import importlib

import pytest

from pipeline_check.core.checks.tekton.base import TektonContext

_HOST_NS_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: t
spec:
  podTemplate:
    hostNetwork: true
  steps:
    - name: s
      image: alpine
"""

_PIPELINE_NO_TIMEOUT = """\
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: a
      taskRef:
        name: x
"""

_TASKRUN_DEFAULT_SA = """\
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  name: r
spec:
  taskRef:
    name: x
"""

_CURL_PIPE_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: t
spec:
  steps:
    - name: s
      image: alpine
      script: |
        curl http://example.com/install.sh | sh
"""

_BUILD_NO_SIGNING = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: build
spec:
  steps:
    - name: build
      image: gcr.io/kaniko-project/executor:latest
      script: |
        docker build -t registry.example/img:latest .
        docker push registry.example/img:latest
"""

_PRIVILEGED_SIDECAR_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: t
spec:
  sidecars:
    - name: dind
      image: docker:dind
      securityContext:
        privileged: true
  steps:
    - name: s
      image: alpine
"""

_WORKSPACE_SUBPATH_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: t
spec:
  workspaces:
    - name: source
      subPath: "$(params.subdir)"
  steps:
    - name: s
      image: alpine
"""

_CASES = {
    "tkn004_host_namespace": _HOST_NS_TASK,
    "tkn006_no_timeout": _PIPELINE_NO_TIMEOUT,
    "tkn007_default_service_account": _TASKRUN_DEFAULT_SA,
    "tkn008_curl_pipe": _CURL_PIPE_TASK,
    "tkn009_signing": _BUILD_NO_SIGNING,
    "tkn010_sbom": _BUILD_NO_SIGNING,
    "tkn011_slsa_provenance": _BUILD_NO_SIGNING,
    "tkn013_sidecar_privileged": _PRIVILEGED_SIDECAR_TASK,
    "tkn015_workspace_subpath_injection": _WORKSPACE_SUBPATH_TASK,
}


@pytest.mark.parametrize("module,manifest", sorted(_CASES.items()))
def test_aggregate_finding_carries_a_location(tmp_path, module, manifest):
    p = tmp_path / "tk.yaml"
    p.write_text(manifest)
    ctx = TektonContext.from_path(p)
    mod = importlib.import_module(
        f"pipeline_check.core.checks.tekton.rules.{module}"
    )
    finding = mod.check(ctx)
    assert not finding.passed, f"{module} should fail on its manifest"
    assert finding.locations, f"{module} should attach a location"
    loc = finding.locations[0]
    assert loc.path == str(p)
    assert loc.start_line is not None and loc.start_line > 0
