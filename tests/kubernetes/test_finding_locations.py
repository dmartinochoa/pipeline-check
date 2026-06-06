"""Source-location coverage for the converted Kubernetes rules.

The aggregate Kubernetes rules historically returned one Finding per check
with ``resource="kubernetes/manifests"`` and no ``Location``, so they
reached the terminal report, SARIF, and the blast-radius heatmap with no
file or line. The workload-level rules (pod security, resources, volumes,
ports, scheduling) now attach one ``Location`` per offender via
``manifest_location``; these tests pin that contract so it can't silently
regress. Each rule is run against a manifest crafted to trip it.
"""
from __future__ import annotations

import importlib

import pytest

from pipeline_check.core.checks.kubernetes.base import KubernetesContext

# A Pod that trips the host-namespace + bare-container rules at once.
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

_HOSTPATH_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: hp
spec:
  volumes:
    - name: host
      hostPath:
        path: /etc
  containers:
    - name: app
      image: app@sha256:aaaa
"""

_ENV_CRED_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: env
spec:
  containers:
    - name: app
      image: app@sha256:aaaa
      env:
        - name: AWS_SECRET
          value: AKIAIOSFODNN7EXAMPLE
"""

_DEPLOYMENT_NO_PROBES = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: app@sha256:aaaa
"""

_PRIORITY_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: pc
  namespace: app
spec:
  priorityClassName: system-cluster-critical
  containers:
    - name: app
      image: app@sha256:aaaa
"""

_HOSTPORT_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: hpport
spec:
  containers:
    - name: app
      image: app@sha256:aaaa
      ports:
        - containerPort: 80
          hostPort: 80
"""

_CONTROL_PLANE_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: cp
  namespace: app
spec:
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
  containers:
    - name: app
      image: app@sha256:aaaa
"""

# Manifest-level rules.
_DEFAULT_NS_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: app@sha256:aaaa
"""

_SSH_SERVICE = """\
apiVersion: v1
kind: Service
metadata:
  name: ssh
spec:
  ports:
    - name: ssh
      port: 22
      targetPort: 22
"""

_BARE_NAMESPACE = """\
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
"""

_INSECURE_INGRESS = """\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  rules:
    - host: example.com
"""

_DEFAULT_SA_BINDING = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bad
  namespace: app
subjects:
  - kind: ServiceAccount
    name: default
    namespace: app
roleRef:
  kind: Role
  name: r
  apiGroup: rbac.authorization.k8s.io
"""

_WEAK_WEBHOOK = """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: weak
webhooks:
  - name: v.example.com
    failurePolicy: Ignore
    rules:
      - apiGroups: ["*"]
        apiVersions: ["*"]
        resources: ["*"]
        operations: ["*"]
"""

# module -> manifest that makes it fail.
_CASES = {
    # batch 1 (pod security)
    "k8s002_host_network": _BAD_POD,
    "k8s003_host_pid": _BAD_POD,
    "k8s004_host_ipc": _BAD_POD,
    "k8s007_run_as_non_root": _BAD_POD,
    "k8s008_read_only_root_fs": _BAD_POD,
    "k8s009_capabilities": _BAD_POD,
    "k8s010_seccomp_profile": _BAD_POD,
    # batch 2 (workload-level)
    "k8s011_service_account": _BAD_POD,
    "k8s012_automount_token": _BAD_POD,
    "k8s014_sensitive_host_path": _HOSTPATH_POD,
    "k8s015_memory_limit": _BAD_POD,
    "k8s016_cpu_limit": _BAD_POD,
    "k8s017_env_credential": _ENV_CRED_POD,
    "k8s024_probes_missing": _DEPLOYMENT_NO_PROBES,
    "k8s025_system_priority_class": _PRIORITY_POD,
    "k8s028_container_host_port": _HOSTPORT_POD,
    "k8s030_control_plane_scheduling": _CONTROL_PLANE_POD,
    # batch 3 (manifest-level)
    "k8s019_default_namespace": _DEFAULT_NS_POD,
    "k8s022_service_ssh": _SSH_SERVICE,
    "k8s023_pod_security_admission": _BARE_NAMESPACE,
    "k8s027_ingress_without_tls": _INSECURE_INGRESS,
    "k8s029_default_sa_binding": _DEFAULT_SA_BINDING,
    "k8s044_admission_webhook_weak": _WEAK_WEBHOOK,
}


@pytest.mark.parametrize("module,manifest", sorted(_CASES.items()))
def test_finding_carries_a_location(tmp_path, module, manifest):
    p = tmp_path / "m.yaml"
    p.write_text(manifest)
    ctx = KubernetesContext.from_path(p)
    mod = importlib.import_module(
        f"pipeline_check.core.checks.kubernetes.rules.{module}"
    )
    finding = mod.check(ctx)
    assert not finding.passed, f"{module} should fail on its manifest"
    assert finding.locations, f"{module} should attach a location"
    loc = finding.locations[0]
    assert loc.path == str(p)
    assert loc.start_line is not None and loc.start_line > 0


def test_location_count_matches_offender_count(tmp_path):
    # Two unhardened containers: K8S-007 should locate each one.
    p = tmp_path / "m.yaml"
    p.write_text(_BAD_POD)
    ctx = KubernetesContext.from_path(p)
    ctx.manifests[0].data["spec"]["containers"].append(
        {"name": "sidecar", "image": "busybox:1"}
    )
    mod = importlib.import_module(
        "pipeline_check.core.checks.kubernetes.rules.k8s007_run_as_non_root"
    )
    finding = mod.check(ctx)
    assert len(finding.locations) == 2
