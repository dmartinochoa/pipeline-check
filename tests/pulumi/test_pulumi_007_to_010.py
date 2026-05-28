"""Per-rule unit tests for PULUMI-007..010 (Pulumi extended pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.pulumi.base import PulumiContext
from pipeline_check.core.checks.pulumi.pipelines import PulumiChecks


def _scan(project_root: pathlib.Path) -> dict:
    ctx = PulumiContext.from_path(str(project_root))
    return {f.check_id: f for f in PulumiChecks(ctx).run()}


def _write_project(
    root: pathlib.Path,
    *,
    project_yaml: str = "name: my-app\nruntime: nodejs\n",
    stack_yamls: dict[str, str] | None = None,
    sources: dict[str, str] | None = None,
) -> None:
    (root / "Pulumi.yaml").write_text(project_yaml, encoding="utf-8")
    for stack_name, body in (stack_yamls or {}).items():
        (root / f"Pulumi.{stack_name}.yaml").write_text(
            body, encoding="utf-8",
        )
    for relpath, body in (sources or {}).items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


# ── PULUMI-007 ──────────────────────────────────────────────────


class TestPULUMI007PublicCloudResource:
    def test_fires_on_s3_public_read_acl(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    'import * as aws from "@pulumi/aws";\n'
                    'const b = new aws.s3.Bucket("d", { acl: "public-read" });\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-007"].passed

    def test_fires_on_gcp_predefined_acl_public(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={
                "__main__.py": (
                    'import pulumi_gcp as gcp\n'
                    'b = gcp.storage.Bucket("d", '
                    'predefined_acl="publicRead")\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-007"].passed

    def test_fires_on_azure_public_access(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    'import * as azure from "@pulumi/azure-native";\n'
                    'new azure.storage.BlobContainer("c", {\n'
                    '    publicAccess: "Container",\n'
                    '});\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-007"].passed

    def test_passes_on_clean_resources(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    'import * as aws from "@pulumi/aws";\n'
                    'const b = new aws.s3.Bucket("d");\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-007"].passed


# ── PULUMI-008 ──────────────────────────────────────────────────


class TestPULUMI008ShellExec:
    def test_fires_on_execSync(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    'import { execSync } from "child_process";\n'
                    'execSync("./deploy.sh");\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-008"].passed

    def test_fires_on_os_system(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={
                "__main__.py": (
                    'import os\n'
                    'os.system("./deploy.sh")\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-008"].passed

    def test_fires_on_subprocess_shell_true(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={
                "__main__.py": (
                    'import subprocess\n'
                    'subprocess.run("./deploy.sh", shell=True)\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-008"].passed

    def test_passes_on_clean_source(self, tmp_path):
        _write_project(
            tmp_path,
            sources={
                "index.ts": (
                    'import * as pulumi from "@pulumi/pulumi";\n'
                    'export const x = "hello";\n'
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-008"].passed


# ── PULUMI-009 ──────────────────────────────────────────────────


class TestPULUMI009RuntimeMismatch:
    def test_fires_when_runtime_mismatches_sources(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: python\n",
            sources={"index.ts": "export const x = 1;\n"},
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-009"].passed

    def test_passes_when_runtime_matches(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: nodejs\n",
            sources={"index.ts": "export const x = 1;\n"},
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-009"].passed

    def test_fires_on_unrecognized_runtime(self, tmp_path):
        _write_project(
            tmp_path,
            project_yaml="name: my-app\nruntime: hypothetical-lang\n",
            sources={"index.ts": "export const x = 1;\n"},
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-009"].passed


# ── PULUMI-010 ──────────────────────────────────────────────────


class TestPULUMI010StackOrphanedSalt:
    def test_fires_when_salt_and_kms_both_present(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "secretsprovider: awskms://alias/p?region=us-east-1\n"
                    "encryptedkey: v1:wrapped-DEK\n"
                    "encryptionsalt: v1:abc:def:gh\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert not findings["PULUMI-010"].passed

    def test_passes_when_only_kms_present(self, tmp_path):
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": (
                    "secretsprovider: awskms://alias/p?region=us-east-1\n"
                    "encryptedkey: v1:wrapped-DEK\n"
                ),
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-010"].passed

    def test_passes_when_only_salt_present(self, tmp_path):
        # Salt without KMS = passphrase posture (PULUMI-001's surface)
        _write_project(
            tmp_path,
            stack_yamls={
                "prod": "encryptionsalt: v1:abc:def:gh\n",
            },
        )
        findings = _scan(tmp_path)
        assert findings["PULUMI-010"].passed

    def test_passes_when_no_stacks(self, tmp_path):
        _write_project(tmp_path)
        findings = _scan(tmp_path)
        assert findings["PULUMI-010"].passed
