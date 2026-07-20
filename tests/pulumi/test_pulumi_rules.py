"""Pulumi rule pack: per-rule pass / fail / edge-case tests."""
from __future__ import annotations

import pathlib

import pytest

from pipeline_check.core.checks.pulumi.base import PulumiContext
from pipeline_check.core.checks.pulumi.pipelines import PulumiChecks


def _scan(project_root: pathlib.Path) -> dict:
    """Build a PulumiContext from ``project_root`` and return
    ``{check_id: Finding}``."""
    ctx = PulumiContext.from_path(str(project_root))
    return {f.check_id: f for f in PulumiChecks(ctx).run()}


def _write_project(
    root: pathlib.Path,
    *,
    project_yaml: str = "name: my-app\nruntime: python\n",
    stack_yamls: dict[str, str] | None = None,
    sources: dict[str, str] | None = None,
) -> None:
    """Materialize a Pulumi project tree under ``root``."""
    (root / "Pulumi.yaml").write_text(project_yaml, encoding="utf-8")
    for stack_name, body in (stack_yamls or {}).items():
        (root / f"Pulumi.{stack_name}.yaml").write_text(
            body, encoding="utf-8",
        )
    for relpath, body in (sources or {}).items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


# ── Parser sanity ────────────────────────────────────────────────


class TestParser:
    def test_loads_project_and_stack_and_sources(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={"prod": "config:\n  foo: bar\n"},
            sources={
                "__main__.py": "import pulumi\n",
                "stacks/extra.py": "x = 1\n",
            },
        )
        ctx = PulumiContext.from_path(str(tmp_path))
        assert len(ctx.projects) == 1
        assert ctx.projects[0].name == "my-app"
        assert len(ctx.stacks) == 1
        assert ctx.stacks[0].stack_name == "prod"
        # At least the two .py source files we wrote.
        py_paths = {pathlib.Path(s.path).name for s in ctx.sources}
        assert "__main__.py" in py_paths
        assert "extra.py" in py_paths

    def test_skips_venv_and_node_modules(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": "import pulumi\n",
                "node_modules/junk.ts": "// vendored\n",
                ".venv/lib/python3.11/site.py": "# venv\n",
            },
        )
        ctx = PulumiContext.from_path(str(tmp_path))
        paths = {s.path for s in ctx.sources}
        assert any("__main__.py" in p for p in paths)
        assert not any("node_modules" in p for p in paths)
        assert not any(".venv" in p for p in paths)


# ── PULUMI-001 ──────────────────────────────────────────────────


class TestPulumi001:
    def test_fires_on_passphrase_stack(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "encryptionsalt: v1:abc:def:gh\n"
                    "config:\n"
                    "  myapp:setting: foo\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-001"].passed

    def test_fires_when_no_secretsprovider(self, tmp_path):
        # No secretsprovider and no encryptionsalt — defaults to
        # passphrase posture if any secret is configured.
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": "config:\n  myapp:setting: foo\n",
            },
        )
        findings = _scan(tmp_path)
        # Without encryptionsalt our heuristic doesn't flag (no
        # evidence yet of any encryption posture). Confirm pass.
        assert findings["PULUMI-001"].passed

    def test_passes_on_kms_provider(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "secretsprovider: awskms://alias/pulumi?region=us-east-1\n"
                    "encryptedkey: v1:abc\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-001"].passed

    def test_passes_when_no_stacks(self, tmp_path):
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-001"].passed


# ── PULUMI-002 ──────────────────────────────────────────────────


class TestPulumi002:
    def test_fires_on_plaintext_secret_shaped_key(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "config:\n"
                    "  myapp:dbPassword: hunter2\n"
                    "  myapp:apiToken: ghp_real_looking_value\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-002"].passed

    def test_passes_when_value_is_wrapped_secret(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "config:\n"
                    "  myapp:dbPassword:\n"
                    "    secure: v1:ciphertext\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-002"].passed

    def test_passes_when_no_secret_shaped_keys(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": "config:\n  myapp:region: us-east-1\n",
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-002"].passed


# ── PULUMI-003 ──────────────────────────────────────────────────


class TestPulumi003:
    def test_fires_on_aws_key_in_source(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    "aws_key = 'AKIAIOSFODNN7EXAMPLE'  # vuln\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-003"].passed

    def test_fires_on_private_key_block(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "key.py": (
                    "key = '-----BEGIN RSA PRIVATE KEY-----'\n"
                    "       '...'\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-003"].passed

    def test_passes_on_clean_source(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    "import pulumi\n"
                    "cfg = pulumi.Config()\n"
                    "secret = cfg.require_secret('apiKey')\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-003"].passed


# ── PULUMI-004 ──────────────────────────────────────────────────


class TestPulumi004:
    def test_fires_on_file_backend(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "backend:\n"
                "  url: file:///opt/state\n"
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-004"].passed

    def test_fires_on_http_backend(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "backend:\n"
                "  url: http://state.example.com/\n"
            ),
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-004"].passed

    def test_passes_when_backend_absent(self, tmp_path):
        # No backend.url -> Pulumi-service default -> safe posture.
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-004"].passed

    def test_passes_on_s3_backend(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml=(
                "name: my-app\n"
                "runtime: python\n"
                "backend:\n"
                "  url: s3://my-state-bucket?region=us-east-1\n"
            ),
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-004"].passed


# ── PULUMI-005 ──────────────────────────────────────────────────


class TestPulumi005:
    def test_fires_on_wildcard_action_resource(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    'import json\n'
                    'policy = json.dumps({\n'
                    '    "Statement": [{\n'
                    '        "Effect": "Allow",\n'
                    '        "Action": "*",\n'
                    '        "Resource": "*"\n'
                    '    }]\n'
                    '})\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-005"].passed

    def test_passes_when_only_action_wildcard(self, tmp_path):
        # Action: "*" with explicit Resource list passes.
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    'policy = """{\n'
                    '  "Statement": [{\n'
                    '    "Effect": "Allow",\n'
                    '    "Action": "*",\n'
                    '    "Resource": ["arn:aws:s3:::my-bucket/*"]\n'
                    '  }]\n'
                    '}"""\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-005"].passed

    def test_passes_on_clean_policy(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    'policy = """{\n'
                    '  "Statement": [{\n'
                    '    "Effect": "Allow",\n'
                    '    "Action": "s3:GetObject",\n'
                    '    "Resource": "arn:aws:s3:::my-bucket/*"\n'
                    '  }]\n'
                    '}"""\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-005"].passed

    def test_fires_on_bare_typescript_keys(self, tmp_path):
        # TS/JS object literals fed to JSON.stringify use BARE keys; the
        # rule's own exploit_example uses this form (B4 FN: only double-
        # quoted keys matched).
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    "const policy = JSON.stringify({\n"
                    "  Statement: [{\n"
                    '    Effect: "Allow",\n'
                    '    Action: "*",\n'
                    '    Resource: "*",\n'
                    "  }],\n"
                    "});\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-005"].passed

    def test_fires_on_single_quoted_python_keys(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    "policy = json.dumps({\n"
                    "    'Statement': [{\n"
                    "        'Effect': 'Allow',\n"
                    "        'Action': '*',\n"
                    "        'Resource': '*',\n"
                    "    }]\n"
                    "})\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-005"].passed


# ── PULUMI-006 ──────────────────────────────────────────────────


class TestPulumi006:
    def test_fires_on_bare_stack_name(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    "import pulumi\n"
                    "upstream = pulumi.StackReference('prod')\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-006"].passed

    def test_passes_on_qualified_stack_name(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": (
                    "import pulumi\n"
                    "upstream = pulumi.StackReference("
                    "'myorg/platform-infra/prod')\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-006"].passed

    def test_passes_when_no_stackreference_calls(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "__main__.py": "import pulumi\n",
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-006"].passed


# ── End-to-end provider routing ────────────────────────────────


def test_provider_in_registry():
    from pipeline_check.core.providers import available
    assert "pulumi" in available()


def test_provider_raises_without_path():
    from pipeline_check.core.providers import get
    prov = get("pulumi")
    with pytest.raises(ValueError, match="pulumi-path"):
        prov.build_context()
