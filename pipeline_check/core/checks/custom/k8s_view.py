"""Synthesized doc shape for Kubernetes/Helm custom rules.

Built-in K8s rules walk a manifest's pod-spec via the kind-specific
helpers in :mod:`...kubernetes.base` (``Pod`` lives at ``spec``,
``Deployment`` at ``spec.template.spec``, ``CronJob`` at
``spec.jobTemplate.spec.template.spec``). A custom rule that wants
to look at "every container" should not have to re-implement those
paths.

This module flattens one :class:`Manifest` into a dict shape that
the DSL can walk uniformly::

    {
      "kind":      "Deployment",
      "name":      "release-app",
      "namespace": "default",
      "api_version": "apps/v1",
      "metadata":  {...},   # raw metadata
      "spec":      {...},   # raw spec
      "raw":       {...},   # the entire parsed doc, escape hatch
      "workloads": [        # 0 or 1 entries (multi-spec resources are rare)
          {
              "kind": "Deployment",
              "name": "release-app",
              "namespace": "default",
              "containers": [          # init + main + ephemeral, normalized
                  {"name": "app", "image": "nginx:latest",
                   "container_kind": "container",
                   "securityContext": {...}, ...},
                  ...
              ],
              "volumes": [...],
              "service_account": "default" | None,
              "host_network": False,
              "host_pid": False,
              "host_ipc": False,
              "spec": {...},   # raw pod spec
          },
      ],
    }

The container's classifier is exposed as ``container_kind`` (values:
``"container"``, ``"initContainer"``, ``"ephemeralContainer"``) so it
doesn't collide with the manifest's ``kind`` field. A custom rule
that iterates ``$.workloads[*].containers[*]`` and writes
``{{kind}}`` in its description gets the manifest kind via the
ambient fallback, not the container classifier.

Non-workload kinds (``Service``, ``Role``, ``Secret``, …) get an
empty ``workloads`` list — the synthesized view doesn't fabricate
data, it only normalizes what's already there.

The dict is built once per manifest per scan and passed to every
custom rule targeted at the kubernetes provider.
"""
from __future__ import annotations

from typing import Any

from ..kubernetes.base import (
    Manifest,
    is_workload,
    iter_containers,
    iter_volumes,
    pod_spec,
)


def manifest_view(m: Manifest) -> dict[str, Any]:
    """Return the synthesized dict shape for a single manifest."""
    workloads: list[dict[str, Any]] = []
    if is_workload(m):
        ps = pod_spec(m)
        if isinstance(ps, dict):
            containers: list[dict[str, Any]] = []
            for kind_label, c in iter_containers(ps):
                containers.append({**c, "container_kind": kind_label})
            workloads.append({
                "kind": m.kind,
                "name": m.name,
                "namespace": m.namespace,
                "containers": containers,
                "volumes": list(iter_volumes(ps)),
                "service_account": ps.get("serviceAccountName"),
                "host_network": ps.get("hostNetwork") is True,
                "host_pid":     ps.get("hostPID") is True,
                "host_ipc":     ps.get("hostIPC") is True,
                "spec": ps,
            })
    metadata = m.data.get("metadata") if isinstance(m.data, dict) else None
    spec = m.data.get("spec") if isinstance(m.data, dict) else None
    return {
        "kind":        m.kind,
        "name":        m.name,
        "namespace":   m.namespace,
        "api_version": m.api_version,
        "metadata":    metadata if isinstance(metadata, dict) else {},
        "spec":        spec if isinstance(spec, dict) else {},
        "raw":         m.data,
        "workloads":   workloads,
    }


__all__ = ["manifest_view"]
