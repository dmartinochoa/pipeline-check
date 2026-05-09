"""Per-rule tests for the Drone CI provider.

Each rule has its own ``Test<RULE_ID>...`` class; inputs are built
inline as Python dicts wrapped in a :class:`Pipeline` so the tests
don't have to round-trip through YAML on disk.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.drone.base import Pipeline
from pipeline_check.core.checks.drone.rules import (
    dr001_image_pinning as r1,
)
from pipeline_check.core.checks.drone.rules import (
    dr002_privileged_step as r2,
)
from pipeline_check.core.checks.drone.rules import (
    dr003_parameter_injection as r3,
)
from pipeline_check.core.checks.drone.rules import (
    dr004_literal_secret as r4,
)
from pipeline_check.core.checks.drone.rules import (
    dr005_plugin_floating_tag as r5,
)
from pipeline_check.core.checks.drone.rules import (
    dr006_tls_bypass as r6,
)

_DIGEST = "@sha256:" + "0" * 64


def _pipeline(
    *,
    type_: str = "docker",
    steps: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
    environment: dict[str, Any] | None = None,
) -> Pipeline:
    data: dict[str, Any] = {
        "kind": "pipeline",
        "type": type_,
        "name": "default",
    }
    if steps is not None:
        data["steps"] = steps
    if services is not None:
        data["services"] = services
    if environment is not None:
        data["environment"] = environment
    return Pipeline(path=".drone.yml", doc_index=0, data=data)


# ── DR-001 ───────────────────────────────────────────────────────────


class TestDR001ImagePinning:
    def test_passes_when_every_image_digest_pinned(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"golang:1.21{_DIGEST}"},
            {"name": "test", "image": f"node:20{_DIGEST}"},
        ])
        assert r1.check(p).passed

    def test_fails_on_floating_tag(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": "golang:latest"},
        ])
        f = r1.check(p)
        assert not f.passed
        assert "golang:latest" in f.description

    def test_fails_on_pinned_version_tag(self) -> None:
        # Specific version tag is not enough; rule wants @sha256.
        p = _pipeline(steps=[
            {"name": "build", "image": "golang:1.21.5"},
        ])
        f = r1.check(p)
        assert not f.passed

    def test_fails_on_no_tag(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": "golang"},
        ])
        f = r1.check(p)
        assert not f.passed

    def test_passes_with_missing_image_field(self) -> None:
        # ``image:`` missing entirely is some other rule's bug.
        p = _pipeline(steps=[{"name": "build"}])
        assert r1.check(p).passed

    def test_passes_on_non_container_pipeline(self) -> None:
        # ``type: ssh`` / ``exec`` runs commands directly, no image.
        p = _pipeline(type_="ssh", steps=[{"name": "x"}])
        assert r1.check(p).passed

    def test_fails_when_service_unpinned(self) -> None:
        p = _pipeline(
            steps=[{"name": "test", "image": f"node:20{_DIGEST}"}],
            services=[{"name": "redis", "image": "redis:7"}],
        )
        f = r1.check(p)
        assert not f.passed
        assert "services.redis" in f.description


# ── DR-002 ───────────────────────────────────────────────────────────


class TestDR002PrivilegedStep:
    def test_passes_without_privileged_flag(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}"},
        ])
        assert r2.check(p).passed

    def test_fails_when_step_privileged_true(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "privileged": True},
        ])
        f = r2.check(p)
        assert not f.passed
        assert "steps.build" in f.description

    def test_fails_when_string_true(self) -> None:
        # YAML loaders sometimes leave booleans as strings; tolerate.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "privileged": "true"},
        ])
        assert not r2.check(p).passed

    def test_passes_when_privileged_false(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "privileged": False},
        ])
        assert r2.check(p).passed

    def test_fails_on_privileged_service(self) -> None:
        p = _pipeline(
            steps=[{"name": "ok", "image": f"x{_DIGEST}"}],
            services=[
                {"name": "docker", "image": f"docker:dind{_DIGEST}",
                 "privileged": True},
            ],
        )
        f = r2.check(p)
        assert not f.passed
        assert "services.docker" in f.description

    def test_passes_on_non_container_pipeline(self) -> None:
        p = _pipeline(type_="exec", steps=[{"name": "x"}])
        assert r2.check(p).passed


# ── DR-003 ───────────────────────────────────────────────────────────


class TestDR003ParameterInjection:
    def test_passes_when_no_drone_var_used(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["go build", "echo done"]},
        ])
        assert r3.check(p).passed

    def test_fails_on_unquoted_drone_pull_request_title(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["echo ${DRONE_PULL_REQUEST_TITLE}"]},
        ])
        assert not r3.check(p).passed

    def test_fails_on_bare_dollar_drone_branch(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["if [ $DRONE_BRANCH = main ]; then ok; fi"]},
        ])
        assert not r3.check(p).passed

    def test_passes_when_double_quoted(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ['echo "${DRONE_PULL_REQUEST_TITLE}"']},
        ])
        assert r3.check(p).passed

    def test_passes_when_single_quoted(self) -> None:
        # Single quotes also tokenise as one argument.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["echo '${DRONE_COMMIT_MESSAGE}'"]},
        ])
        assert r3.check(p).passed

    def test_passes_on_trusted_drone_var(self) -> None:
        # ``DRONE_BUILD_NUMBER`` isn't user-controllable.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["echo $DRONE_BUILD_NUMBER"]},
        ])
        assert r3.check(p).passed

    def test_fails_on_drone_commit_message(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["echo ${DRONE_COMMIT_MESSAGE}"]},
        ])
        assert not r3.check(p).passed


# ── DR-004 ───────────────────────────────────────────────────────────


class TestDR004LiteralSecret:
    def test_passes_with_from_secret_reference(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "environment": {"API_TOKEN": {"from_secret": "api_token"}}},
        ])
        assert r4.check(p).passed

    def test_fails_on_literal_token_value(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "environment": {"API_TOKEN": "sk-secret-1234567890"}},
        ])
        f = r4.check(p)
        assert not f.passed
        assert "API_TOKEN" in f.description

    def test_fails_on_literal_password_in_settings(self) -> None:
        p = _pipeline(steps=[
            {"name": "publish", "image": f"plugins/docker{_DIGEST}",
             "settings": {"username": "foo", "password": "literal-pw"}},
        ])
        f = r4.check(p)
        assert not f.passed
        assert "settings.password" in f.description

    def test_passes_on_empty_string_value(self) -> None:
        # Empty value is a config bug, not a leak.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "environment": {"API_TOKEN": ""}},
        ])
        assert r4.check(p).passed

    def test_fails_on_aws_akia_key_regardless_of_key_name(self) -> None:
        p = _pipeline(steps=[
            {"name": "deploy", "image": f"x{_DIGEST}",
             "environment": {"FOO": "AKIAIOSFODNN7EXAMPLE"}},
        ])
        f = r4.check(p)
        assert not f.passed
        assert "AKIA prefix" in f.description

    def test_passes_on_non_credential_keys(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "environment": {"GOFLAGS": "-mod=vendor",
                             "BUILD_ID": "12345"}},
        ])
        assert r4.check(p).passed

    def test_fails_when_pipeline_environment_carries_literal(self) -> None:
        # Pipeline-level ``environment:`` is also scanned.
        p = _pipeline(
            steps=[{"name": "build", "image": f"x{_DIGEST}"}],
            environment={"DEPLOY_TOKEN": "literal-secret-9999"},
        )
        f = r4.check(p)
        assert not f.passed
        assert "pipeline.environment.DEPLOY_TOKEN" in f.description

    def test_passes_on_auth_substring_keys(self) -> None:
        # ``OAUTH2_CLIENT_ID`` / ``AUTHOR_NAME`` / ``AUTHENTICATION_*``
        # all contain ``auth`` as a substring but are not credentials.
        # The vocabulary anchors on segment boundaries so they don't
        # fire (the ``auth`` substring isn't a separate segment).
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "environment": {
                "OAUTH2_CLIENT_ID": "client-id-abc-12345",
                "AUTHOR_NAME": "Some Person Long Name",
                "AUTHENTICATION_REQUIRED": "true",
                "OAUTH_FLOW": "authorization_code",
            }},
        ])
        assert r4.check(p).passed

    def test_passes_on_short_credential_value(self) -> None:
        # ``API_TOKEN: "true"`` is a config flag, not a leak. The
        # length floor + placeholder filter catches both shapes.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "environment": {
                "API_TOKEN": "true",
                "DOCKER_PASSWORD": "n/a",
                "BUILD_TOKEN": "1",
            }},
        ])
        assert r4.check(p).passed

    def test_passes_on_interpolated_reference(self) -> None:
        # ``${SECRET_FROM_HOOK}`` shape isn't a literal credential
        # even though Drone prefers ``from_secret:``.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "environment": {
                "API_TOKEN": "${SECRET_FROM_HOOK}",
                "DEPLOY_KEY": "$DEPLOY_KEY_FROM_RUNNER",
            }},
        ])
        assert r4.check(p).passed

    def test_passes_when_keynote_or_keynumber_keys(self) -> None:
        # ``KEYNOTE`` / ``KEY_NUMBER`` contain ``key`` substrings but
        # aren't credential fields. Verifying the segment-boundary
        # anchoring works in both directions.
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}", "environment": {
                "KEYNOTE_SPEAKER": "Long Speaker Name Goes Here",
                "KEY_NUMBER": "long-string-not-a-secret",
            }},
        ])
        assert r4.check(p).passed


# ── DR-005 ───────────────────────────────────────────────────────────


class TestDR005PluginFloatingTag:
    def test_passes_on_pinned_version_tag(self) -> None:
        p = _pipeline(steps=[
            {"name": "publish", "image": "plugins/docker:20.13.0",
             "settings": {"repo": "x"}},
        ])
        assert r5.check(p).passed

    def test_passes_on_digest_pinned(self) -> None:
        p = _pipeline(steps=[
            {"name": "publish",
             "image": f"plugins/docker:20.13.0{_DIGEST}",
             "settings": {"repo": "x"}},
        ])
        assert r5.check(p).passed

    def test_fails_on_floating_tag(self) -> None:
        p = _pipeline(steps=[
            {"name": "publish", "image": "plugins/docker:latest",
             "settings": {"repo": "x"}},
        ])
        f = r5.check(p)
        assert not f.passed
        assert "plugins/docker:latest" in f.description

    def test_fails_on_no_tag(self) -> None:
        p = _pipeline(steps=[
            {"name": "publish", "image": "plugins/docker",
             "settings": {"repo": "x"}},
        ])
        assert not r5.check(p).passed

    def test_passes_on_step_without_settings_block(self) -> None:
        # Plain step, not a plugin step. Image pinning is DR-001's
        # job; DR-005 shouldn't fire.
        p = _pipeline(steps=[
            {"name": "build", "image": "golang:latest"},
        ])
        assert r5.check(p).passed


# ── DR-006 ───────────────────────────────────────────────────────────


class TestDR006TLSBypass:
    def test_passes_when_no_bypass(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["curl https://example.com"]},
        ])
        assert r6.check(p).passed

    def test_fails_on_curl_insecure(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["curl --insecure https://example.com"]},
        ])
        assert not r6.check(p).passed

    def test_fails_on_curl_dash_k(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["curl -k https://example.com"]},
        ])
        assert not r6.check(p).passed

    def test_fails_on_wget_no_check_certificate(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["wget --no-check-certificate "
                          "https://example.com/x.tar"]},
        ])
        assert not r6.check(p).passed

    def test_fails_on_git_sslverify_false(self) -> None:
        p = _pipeline(steps=[
            {"name": "build", "image": f"x{_DIGEST}",
             "commands": ["git config http.sslverify false"]},
        ])
        assert not r6.check(p).passed

    def test_passes_on_non_container_pipeline(self) -> None:
        p = _pipeline(type_="exec", steps=[{"name": "x"}])
        assert r6.check(p).passed
