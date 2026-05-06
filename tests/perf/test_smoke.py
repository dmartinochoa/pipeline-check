"""Lightweight performance smoke tests.

Catches catastrophic regressions (an O(n) rule that becomes O(n²),
a per-step regex compile that should have been module-level, etc.)
without taking on a ``pytest-benchmark`` dependency. The thresholds
are deliberately generous so the test isn't flaky on slow runners;
the goal is to fail when something regresses by an order of
magnitude, not to micro-benchmark.

Each test:
1. Builds a synthetic but realistic input of a fixed size.
2. Runs the orchestrator N times, taking the median wall time.
3. Asserts the median sits under a runner-stable ceiling.

The ceilings were measured locally and padded ~5x. CI runners are
slower than dev boxes; if a test goes flaky, push the ceiling up
rather than chasing the regression. A real regression will
typically blow past even a 5x pad.
"""
from __future__ import annotations

import statistics
import time

from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.kubernetes.base import KubernetesContext, Manifest
from pipeline_check.core.checks.kubernetes.manifests import (
    KubernetesManifestChecks,
)

# Generous ceiling — we want to catch order-of-magnitude regressions,
# not jitter. CI runners are routinely 2-3x slower than dev; the
# 5-second number leaves headroom for that without hiding real
# breakage (a bad rule typically pushes the same workload past 30+s).
_GHA_500_JOBS_CEILING_S = 5.0
_K8S_500_PODS_CEILING_S = 5.0
_RUNS = 3  # median of N runs to absorb GC / scheduler jitter


def _median_runtime(invoke, runs: int = _RUNS) -> float:
    """Return the median wall time of ``invoke()`` over ``runs`` calls."""
    samples: list[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        invoke()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def _synthetic_gha_workflow(num_jobs: int) -> dict:
    """Build a workflow doc with ``num_jobs`` jobs, each with 4 steps.

    Mix of pinned actions, run steps, env blocks — exercises the
    canonical rule surface (pinning, secrets, OIDC, container
    options, package integrity). Roughly 1.5k lines when serialized
    at num_jobs=500.
    """
    jobs: dict = {}
    for i in range(num_jobs):
        jobs[f"job{i}"] = {
            "runs-on": "ubuntu-22.04",
            "timeout-minutes": 10,
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": [
                {
                    "uses": "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
                },
                {
                    "uses": "actions/setup-python@v5.1.0",
                    "with": {"python-version": "3.12"},
                },
                {"run": "pip install --require-hashes -r requirements.txt"},
                {
                    "run": "pytest -q",
                    "env": {"PYTHONHASHSEED": "0"},
                },
            ],
        }
    return {
        "name": "synthetic",
        "on": {"push": {"branches": ["main"]}},
        "jobs": jobs,
    }


def _synthetic_k8s_manifest(name: str, idx: int) -> Manifest:
    """Build one Deployment-shaped manifest with a non-default SA.

    Constructed via ``Manifest`` directly so we don't pay the YAML
    parse cost — we want to measure the rule pipeline, not the
    parser.
    """
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "prod"},
        "spec": {
            "template": {
                "spec": {
                    "serviceAccountName": "app-sa",
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "c",
                        "image": (
                            "nginx@sha256:"
                            "0000000000000000000000000000000000000000"
                            "000000000000000000000001"
                        ),
                        "securityContext": {
                            "runAsNonRoot": True,
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "limits": {"cpu": "500m", "memory": "256Mi"},
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                        },
                    }],
                },
            },
        },
    }
    return Manifest(
        path=f"manifests/{name}.yaml",
        doc_index=idx,
        api_version="apps/v1",
        kind="Deployment",
        name=name,
        namespace="prod",
        data=doc,
    )


def test_gha_500_jobs_under_ceiling():
    """Scanning a 500-job GHA workflow stays under the runtime ceiling."""
    doc = _synthetic_gha_workflow(num_jobs=500)
    ctx = GitHubContext([Workflow(path="wf.yml", data=doc)])

    median = _median_runtime(lambda: list(WorkflowChecks(ctx).run()))

    assert median < _GHA_500_JOBS_CEILING_S, (
        f"GHA scan of 500 jobs took median {median:.2f}s, "
        f"ceiling is {_GHA_500_JOBS_CEILING_S:.1f}s. "
        f"Investigate which rule regressed (try bisecting "
        f"WorkflowChecks._discover_rules)."
    )


def test_k8s_500_manifests_under_ceiling():
    """Scanning 500 K8s manifests stays under the runtime ceiling."""
    manifests = [_synthetic_k8s_manifest(f"app-{i}", i) for i in range(500)]
    ctx = KubernetesContext(manifests)

    median = _median_runtime(lambda: list(KubernetesManifestChecks(ctx).run()))

    assert median < _K8S_500_PODS_CEILING_S, (
        f"K8s scan of 500 manifests took median {median:.2f}s, "
        f"ceiling is {_K8S_500_PODS_CEILING_S:.1f}s."
    )
