"""Regression tests from the 2026-07 rule audit (Drone)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.drone.base import Pipeline
from pipeline_check.core.checks.drone.rules import dr004_literal_secret as r04
from pipeline_check.core.checks.drone.rules import dr007_host_path_mount as r07
from pipeline_check.core.checks.drone.rules import (
    dr016_image_field_interpolation as r16,
)
from pipeline_check.core.checks.drone.rules import dr017_shell_eval as r17


def _pipeline(**data: Any) -> Pipeline:
    body: dict[str, Any] = {"kind": "pipeline", "type": "docker", "name": "d"}
    body.update(data)
    return Pipeline(path=".drone.yml", doc_index=0, data=body)


def test_dr016_bare_dollar_var_image_interpolation():
    p = _pipeline(steps=[{"name": "b", "image": "registry/app:$DRONE_TAG"}])
    assert r16.check(p).passed is False
    # ``$$`` escape is a literal dollar, not interpolation
    ok = _pipeline(steps=[{"name": "b", "image": "registry/app:latest"}])
    assert r16.check(ok).passed is True


def test_dr017_positional_param_not_flagged():
    # ``exec "$@"`` is the documented-safe positional expansion.
    p = _pipeline(steps=[{"name": "b", "image": "alpine",
                          "commands": ["sh -c 'exec \"$@\"'"]}])
    assert r17.check(p).passed is True
    # a real shell-on-variable re-invocation still fires
    bad = _pipeline(steps=[{"name": "b", "image": "alpine",
                            "commands": ["sh -c $USER_INPUT"]}])
    assert r17.check(bad).passed is False


def test_dr004_nested_settings_literal_secret():
    # A literal credential buried in a nested plugin ``settings:`` sub-map
    # was skipped (no recursion). It must now be classified.
    p = _pipeline(steps=[{
        "name": "publish", "image": "plugins/webhook",
        "settings": {"config": {"password": "literal-pass-9999"}},
    }])
    assert r04.check(p).passed is False
    # a nested ``from_secret`` ref stays safe
    ok = _pipeline(steps=[{
        "name": "publish", "image": "plugins/webhook",
        "settings": {"config": {"password": {"from_secret": "webhook_pw"}}},
    }])
    assert r04.check(ok).passed is True


def test_dr007_runtime_socket_scoping():
    # A benign app socket under /var/run no longer fires...
    ok = _pipeline(
        steps=[{"name": "b", "image": "alpine",
                "volumes": [{"name": "s", "path": "/var/run/myapp.sock"}]}],
        volumes=[{"name": "s", "host": {"path": "/var/run/myapp.sock"}}],
    )
    assert r07.check(ok).passed is True
    # ...but the container-runtime sockets (docker / containerd) still fire.
    for host_path in ("/var/run/docker.sock",
                      "/var/run/containerd/containerd.sock"):
        bad = _pipeline(
            steps=[{"name": "b", "image": "docker",
                    "volumes": [{"name": "s", "path": host_path}]}],
            volumes=[{"name": "s", "host": {"path": host_path}}],
        )
        assert r07.check(bad).passed is False, host_path
