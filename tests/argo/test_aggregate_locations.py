"""Source-location coverage for the aggregate Argo Workflows rules.

These rules emit one Finding per check and used to set ``resource="argo"``
with no ``Location`` (ARGO-001/002 were the exception, ARGO-005/017 are
backfilled from their ``job_anchors``). They now attach one ``Location``
per offending document via ``doc_location``. Each rule is driven by a
manifest crafted to trip it.
"""
from __future__ import annotations

import importlib

import pytest

from pipeline_check.core.checks.argo.base import ArgoContext

_BASIC = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  templates:
    - name: main
      container:
        image: alpine
"""

_HOSTPATH = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  volumes:
    - name: host
      hostPath:
        path: /etc
  templates:
    - name: main
      container:
        image: alpine
"""

_ENV_SECRET = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  templates:
    - name: main
      container:
        image: alpine
        env:
          - name: TOKEN
            value: "ghp_0123456789012345678901234567890123"
"""

_CURL_PIPE = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  templates:
    - name: main
      script:
        image: alpine
        source: |
          curl http://example.com/install.sh | sh
"""

_BUILD = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: build
spec:
  entrypoint: main
  templates:
    - name: main
      script:
        image: gcr.io/kaniko-project/executor:latest
        source: |
          docker build -t registry.example/img:latest .
          docker push registry.example/img:latest
"""

_PKG_UNPINNED = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  templates:
    - name: main
      script:
        image: python:3.12
        source: |
          pip install requests
"""

_INSECURE_ARTIFACT = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  templates:
    - name: main
      inputs:
        artifacts:
          - name: src
            path: /src
            http:
              url: "http://example.com/file.tar"
      container:
        image: alpine
"""

_ADMIN_SA = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  entrypoint: main
  serviceAccountName: cluster-admin
  templates:
    - name: main
      container:
        image: alpine
"""

_CASES = {
    "argo003_default_service_account": _BASIC,
    "argo004_host_namespace": _HOSTPATH,
    "argo006_literal_secrets": _ENV_SECRET,
    "argo007_no_deadline": _BASIC,
    "argo008_curl_pipe": _CURL_PIPE,
    "argo009_signing": _BUILD,
    "argo010_sbom": _BUILD,
    "argo011_slsa_provenance": _BUILD,
    "argo013_automount_token": _BASIC,
    "argo014_pkg_unpinned": _PKG_UNPINNED,
    "argo015_artifact_insecure_url": _INSECURE_ARTIFACT,
    "argo016_cluster_admin_service_account": _ADMIN_SA,
}


@pytest.mark.parametrize("module,manifest", sorted(_CASES.items()))
def test_aggregate_finding_carries_a_location(tmp_path, module, manifest):
    p = tmp_path / "wf.yaml"
    p.write_text(manifest)
    ctx = ArgoContext.from_path(p)
    mod = importlib.import_module(
        f"pipeline_check.core.checks.argo.rules.{module}"
    )
    finding = mod.check(ctx)
    assert not finding.passed, f"{module} should fail on its manifest"
    assert finding.locations, f"{module} should attach a location"
    loc = finding.locations[0]
    assert loc.path == str(p)
    assert loc.start_line is not None and loc.start_line > 0
