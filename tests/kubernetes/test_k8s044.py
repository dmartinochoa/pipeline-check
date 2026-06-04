"""Tests for K8S-044 (admission webhook fail-open / unscoped mutating)."""
from __future__ import annotations

import textwrap

import yaml

from pipeline_check.core.checks.kubernetes.base import KubernetesContext, Manifest
from pipeline_check.core.checks.kubernetes.rules import (
    k8s044_admission_webhook_weak as rule,
)


def _ctx(yaml_text: str) -> KubernetesContext:
    docs = list(yaml.safe_load_all(textwrap.dedent(yaml_text)))
    manifests = []
    for idx, d in enumerate(docs):
        if not isinstance(d, dict):
            continue
        meta = d.get("metadata") or {}
        manifests.append(Manifest(
            path="webhooks.yaml", doc_index=idx,
            api_version=d.get("apiVersion", ""), kind=d.get("kind", ""),
            name=meta.get("name", "") if isinstance(meta, dict) else "",
            namespace=meta.get("namespace", "") if isinstance(meta, dict) else "",
            data=d,
        ))
    return KubernetesContext(manifests)


def _run(yaml_text: str):
    return rule.check(_ctx(yaml_text))


class TestK8S044:
    def test_fails_on_failopen_broad_webhook(self):
        f = _run("""
        apiVersion: admissionregistration.k8s.io/v1
        kind: ValidatingWebhookConfiguration
        metadata: {name: guard}
        webhooks:
          - name: g.example.com
            failurePolicy: Ignore
            rules:
              - apiGroups: [""]
                apiVersions: [v1]
                operations: [CREATE]
                resources: [pods]
        """)
        assert not f.passed

    def test_fails_on_unscoped_mutating_webhook(self):
        f = _run("""
        apiVersion: admissionregistration.k8s.io/v1
        kind: MutatingWebhookConfiguration
        metadata: {name: inject}
        webhooks:
          - name: inj.example.com
            rules:
              - apiGroups: [""]
                apiVersions: [v1]
                operations: [CREATE]
                resources: [pods]
        """)
        assert not f.passed

    def test_passes_on_failclosed_scoped_webhook(self):
        f = _run("""
        apiVersion: admissionregistration.k8s.io/v1
        kind: ValidatingWebhookConfiguration
        metadata: {name: guard}
        webhooks:
          - name: g.example.com
            failurePolicy: Fail
            namespaceSelector: {matchLabels: {policy: enforced}}
            rules:
              - apiGroups: [""]
                apiVersions: [v1]
                operations: [CREATE]
                resources: [pods]
        """)
        assert f.passed

    def test_passes_on_scoped_mutating_webhook(self):
        f = _run("""
        apiVersion: admissionregistration.k8s.io/v1
        kind: MutatingWebhookConfiguration
        metadata: {name: inject}
        webhooks:
          - name: inj.example.com
            namespaceSelector: {matchLabels: {inject: enabled}}
            rules:
              - apiGroups: [""]
                apiVersions: [v1]
                operations: [CREATE]
                resources: [pods]
        """)
        assert f.passed

    def test_passes_on_narrow_failopen_crd_webhook(self):
        # A fail-open webhook scoped to a single CRD is low-risk: it
        # doesn't intercept pods or a broad apiGroup.
        f = _run("""
        apiVersion: admissionregistration.k8s.io/v1
        kind: ValidatingWebhookConfiguration
        metadata: {name: cm-guard}
        webhooks:
          - name: cm.example.com
            failurePolicy: Ignore
            rules:
              - apiGroups: [example.com]
                apiVersions: [v1]
                operations: [CREATE]
                resources: [widgets]
        """)
        assert f.passed

    def test_passes_with_no_webhook_configs(self):
        f = _run("""
        apiVersion: v1
        kind: Pod
        metadata: {name: p}
        spec:
          containers:
            - name: c
              image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001
        """)
        assert f.passed
