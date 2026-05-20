"""Per-rule tests for K8s container resource limits and env-var secrets:
K8S-015 (memory limit), K8S-016 (CPU limit),
K8S-017 (env value carries credential-shaped literal),
K8S-018 (Secret carries plaintext credential).

The first two rules cap a compromised container's blast radius by
keeping it from starving the node. The last two flag credentials
that live in the manifest YAML where every reader of
``kubectl get -o yaml`` (or every git history viewer) sees them.
"""
from __future__ import annotations

from .conftest import pod, run_check

_BASE_IMAGE = "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000001"


# ── K8S-015 memory limit ────────────────────────────────────────────


class TestK8S015MemoryLimit:
    def test_fails_when_no_memory_limit_set(self):
        f = run_check(pod(), "K8S-015")
        assert not f.passed

    def test_fails_when_only_cpu_limit_set(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "resources": {"limits": {"cpu": "500m"}},
        }]), "K8S-015")
        assert not f.passed

    def test_passes_with_memory_limit(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "resources": {
                "limits": {"memory": "256Mi", "cpu": "500m"},
                "requests": {"memory": "128Mi"},
            },
        }]), "K8S-015")
        assert f.passed


# ── K8S-016 CPU limit ───────────────────────────────────────────────


class TestK8S016CPULimit:
    def test_fails_when_no_cpu_limit_set(self):
        f = run_check(pod(), "K8S-016")
        assert not f.passed

    def test_fails_when_only_memory_limit_set(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "resources": {"limits": {"memory": "256Mi"}},
        }]), "K8S-016")
        assert not f.passed

    def test_passes_with_cpu_limit(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "resources": {
                "limits": {"memory": "256Mi", "cpu": "500m"},
            },
        }]), "K8S-016")
        assert f.passed


# ── K8S-017 env value carries credential literal ────────────────────


class TestK8S017EnvCredentialLiteral:
    def test_fails_when_aws_key_in_env_value(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"name": "AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE"},
            ],
        }]), "K8S-017")
        assert not f.passed

    def test_passes_with_secret_key_ref(self):
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [{
                "name": "AWS_ACCESS_KEY_ID",
                "valueFrom": {"secretKeyRef": {
                    "name": "aws-creds", "key": "access_key_id",
                }},
            }],
        }]), "K8S-017")
        assert f.passed

    def test_passes_with_no_env_block(self):
        f = run_check(pod(), "K8S-017")
        assert f.passed

    def test_fails_when_secretish_name_has_literal_value(self):
        # SECRETISH_KEY_RE catches credential-shaped names (here:
        # ``API_KEY``); the value is a plain literal so the rule
        # offends.
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"name": "API_KEY", "value": "live-key-not-a-ref"},
            ],
        }]), "K8S-017")
        assert not f.passed
        assert "API_KEY" in f.description

    def test_passes_when_secretish_name_uses_downward_api(self):
        # ``$(VAR)`` is K8s downward-API substitution, not a literal.
        # ``_looks_literal`` must reject it so the rule passes.
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"name": "API_KEY", "value": "$(POD_NAME)"},
            ],
        }]), "K8S-017")
        assert f.passed

    def test_passes_when_secretish_name_has_empty_value(self):
        # An empty string is structurally distinct from a literal —
        # ``_looks_literal`` rejects it so the rule passes (the env
        # entry is effectively a placeholder, not a real credential).
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"name": "API_KEY", "value": ""},
            ],
        }]), "K8S-017")
        assert f.passed

    def test_passes_when_env_entry_lacks_name(self):
        # Defensive against malformed manifests: an env entry with no
        # ``name`` is skipped without firing.
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"value": "AKIAIOSFODNN7EXAMPLE"},  # no name key
            ],
        }]), "K8S-017")
        assert f.passed

    def test_passes_when_env_list_carries_non_dict_entry(self):
        # K8s rejects this manifest itself, but the rule mustn't
        # crash on it. The non-dict entry is skipped.
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                "not-a-dict",
                {"name": "SAFE", "value": "x"},
            ],
        }]), "K8S-017")
        assert f.passed

    def test_passes_when_secretish_name_has_non_string_value(self):
        # K8s typically coerces, but a manifest fragment may carry an
        # int / list under ``value``. ``_looks_literal`` rejects
        # non-strings so the rule passes (the offender path needs a
        # string to compare).
        f = run_check(pod(containers=[{
            "name": "c",
            "image": _BASE_IMAGE,
            "env": [
                {"name": "API_KEY", "value": 42},
            ],
        }]), "K8S-017")
        assert f.passed


# ── K8S-018 Secret carries plaintext credential ─────────────────────


class TestK8S018SecretLiteral:
    def test_fails_on_secret_string_data_with_aws_key(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "aws", "namespace": "default"},
            "type": "Opaque",
            "stringData": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
        }
        f = run_check(secret, "K8S-018")
        assert not f.passed

    def test_passes_when_string_data_is_non_credential(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cfg", "namespace": "default"},
            "type": "Opaque",
            "stringData": {"CONFIG_PROFILE": "production"},
        }
        f = run_check(secret, "K8S-018")
        assert f.passed
