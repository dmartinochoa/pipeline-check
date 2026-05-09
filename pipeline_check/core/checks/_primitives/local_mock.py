"""Detect "this env block is talking to a local mock service."

Integration tests against LocalStack / Moto / kind / k3d set
``AWS_ENDPOINT_URL`` (and friends) to a localhost address so the
service SDKs talk to the local container instead of real cloud.
Several rules need to recognize this shape so they don't false-
positive on test workflows: GHA-005 should not flag the LocalStack
sentinel ``test`` access keys, GHA-014 should not require an
``environment:`` gate on a ``terraform apply`` against LocalStack,
and any future rule with the same flavor of FP risk should not have
to re-implement the same detection logic.

The helpers here answer two questions:

  1. Does this env block point an AWS / k8s endpoint at localhost?
     (:func:`env_targets_local_mock`)
  2. Are this env block's AWS access keys the LocalStack sentinel
     literal ``"test"``? (:func:`env_has_localstack_sentinel`)

Detection is structural and conservative. We require the endpoint
to literally start with a localhost host (``localhost``, ``127.0.0.1``,
``0.0.0.0``, ``::1``) — a custom DNS name like ``mock.internal``
that resolves to localhost is not currently matched, because any
match here suppresses real findings and a coincidental private
DNS name shouldn't earn that suppression by accident.
"""
from __future__ import annotations

import re
from typing import Any

# Endpoints that signal "deploying to a local mock" (LocalStack, Moto,
# kind, k3d, minikube). The match is anchored at the start so a URL
# like ``http://api.example.com/?endpoint=http://localhost`` doesn't
# trip the suppression.
LOCAL_ENDPOINT_RE = re.compile(
    r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"
    r"(?::\d+)?(?:/|$)",
    re.IGNORECASE,
)


# Env var names that route a service SDK at a non-default endpoint.
# AWS_ENDPOINT_URL is the universal boto3 / aws-sdk override; the
# per-service variants exist for AWS clients that need to split the
# routing across services. KUBE_API_URL covers kubectl talking to a
# local cluster.
_LOCAL_MOCK_ENV_KEYS: tuple[str, ...] = (
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_S3",
    "KUBE_API_URL",
)


def env_targets_local_mock(env: Any) -> bool:
    """True when *env* points an AWS / k8s endpoint at localhost.

    *env* is whatever the YAML parser returned for an ``env:`` block:
    typically a ``dict[str, str]`` but defensively handle anything.
    """
    if not isinstance(env, dict):
        return False
    for key in _LOCAL_MOCK_ENV_KEYS:
        v = env.get(key)
        if isinstance(v, str) and LOCAL_ENDPOINT_RE.match(v):
            return True
    return False


# Sentinel access-key values that LocalStack and Moto document as
# placeholder credentials. Real AWS rejects literal ``test`` /
# ``testing`` immediately, so the combination of a localhost
# endpoint + one of these is unambiguous.
_LOCALSTACK_SENTINEL_VALUES: frozenset[str] = frozenset({"test", "testing"})


def env_has_localstack_sentinel(env: Any) -> bool:
    """True when *env* carries LocalStack's documented sentinel
    AWS credentials (``test`` / ``test``) alongside a localhost
    endpoint.

    Both signals are required: a workflow that hardcodes ``test``
    keys without redirecting the endpoint is talking to real AWS
    (and will fail at runtime), so the keys still represent a
    leak-shape and shouldn't be suppressed.
    """
    if not isinstance(env, dict):
        return False
    if not env_targets_local_mock(env):
        return False
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        v = env.get(key)
        if isinstance(v, str) and v.strip().lower() not in _LOCALSTACK_SENTINEL_VALUES:
            return False
    return True
