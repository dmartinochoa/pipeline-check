"""Source-location coverage for the pod-security Kubernetes rules.

The aggregate Kubernetes rules historically returned one Finding per check
with ``resource="kubernetes/manifests"`` and no ``Location``, so they
reached the terminal report, SARIF, and the blast-radius heatmap with no
file or line. The pod-security cluster (host namespaces + securityContext)
now attaches one ``Location`` per offender via ``manifest_location``; these
tests pin that contract so it can't silently regress.
"""
from __future__ import annotations

import importlib

import pytest

from pipeline_check.core.checks.kubernetes.base import KubernetesContext

# Rules converted in this batch and the offending manifest each fires on.
_RULES = [
    "k8s002_host_network",
    "k8s003_host_pid",
    "k8s004_host_ipc",
    "k8s007_run_as_non_root",
    "k8s008_read_only_root_fs",
    "k8s009_capabilities",
    "k8s010_seccomp_profile",
]

# One Pod that trips every rule above: host namespaces on, and a container
# with no securityContext (so runAsNonRoot / readOnlyRootFilesystem /
# capabilities / seccomp all fail).
_BAD_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: app
      image: nginx:latest
"""


@pytest.fixture
def ctx(tmp_path):
    p = tmp_path / "pod.yaml"
    p.write_text(_BAD_POD)
    return KubernetesContext.from_path(p), str(p)


@pytest.mark.parametrize("module", _RULES)
def test_pod_security_finding_carries_a_location(ctx, module):
    context, path = ctx
    mod = importlib.import_module(
        f"pipeline_check.core.checks.kubernetes.rules.{module}"
    )
    finding = mod.check(context)
    assert not finding.passed, f"{module} should fail on the bad pod"
    assert finding.locations, f"{module} should attach a location"
    loc = finding.locations[0]
    assert loc.path == path
    assert loc.start_line is not None and loc.start_line > 0


def test_location_count_matches_offender_count(ctx):
    # Two containers, both unhardened: K8S-007 should locate each one.
    context, path = ctx
    # Add a second container so the offender list has two entries.
    context.manifests[0].data["spec"]["containers"].append(
        {"name": "sidecar", "image": "busybox:1"}
    )
    mod = importlib.import_module(
        "pipeline_check.core.checks.kubernetes.rules.k8s007_run_as_non_root"
    )
    finding = mod.check(context)
    assert len(finding.locations) == 2
