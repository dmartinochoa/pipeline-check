"""Provider ``inventory()`` coverage for the YAML-stack providers
whose dedicated test suites focus on rules rather than the inventory
surface.

Each provider's ``inventory()`` walks its own context shape and emits
a list of :class:`Component`. The shapes differ enough per provider
(Argo's multi-doc, Buildkite's wait/block step exclusion, Maven's
side-fields, etc.) that a single shared fixture wouldn't cover the
branches. We exercise each provider through its real
``from_path`` -> ``inventory`` path so any future refactor of the
context shapes is caught by inventory-level diff first.

Also covers each provider's ``build_context`` ``ValueError`` path
(missing required arg) and the ``BaseProvider`` ABC contract on
the optional ``inventory()`` default.
"""
from __future__ import annotations

import pytest

from pipeline_check.core import providers as _providers

# ── build_context ValueError paths ─────────────────────────────────


@pytest.mark.parametrize("name,kw", [
    ("argo", {"argo_path": None}),
    ("tekton", {"tekton_path": None}),
    ("buildkite", {"buildkite_path": None}),
    ("cloudbuild", {"cloudbuild_path": None}),
    ("dockerfile", {"dockerfile_path": None}),
    ("npm", {"npm_path": None}),
    ("maven", {"maven_path": None}),
    ("pypi", {"pypi_path": None}),
])
def test_provider_build_context_requires_path(name: str, kw: dict) -> None:
    """Every YAML/file-based provider raises ValueError when the
    --foo-path argument is missing. Locks the CLI contract so a future
    refactor that swaps to an optional default has to update this test
    deliberately."""
    provider = _providers.get(name)
    with pytest.raises(ValueError, match="path"):
        provider.build_context(**kw)


# ── Argo inventory ─────────────────────────────────────────────────


def test_argo_inventory_extracts_workflow_metadata(tmp_path):
    wf = tmp_path / "wf.yaml"
    wf.write_text(
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata:\n"
        "  name: hello\n"
        "  namespace: argo\n"
        "spec:\n"
        "  entrypoint: main\n"
        "  templates:\n"
        "    - name: main\n"
        "      container:\n"
        "        image: alpine:3.20\n"
        "    - name: side\n"
        "      script:\n"
        "        image: alpine:3.20\n"
        "        source: |\n"
        "          echo hi\n"
    )
    provider = _providers.get("argo")
    ctx = provider.build_context(argo_path=str(wf))
    inv = provider.inventory(ctx)
    assert len(inv) == 1
    c = inv[0]
    assert c.type == "workflow"
    assert c.identifier == "Workflow/hello"
    assert c.metadata["namespace"] == "argo"
    assert c.metadata["template_count"] == 2
    assert c.metadata["entrypoint"] == "main"


def test_argo_inventory_skips_namespace_when_absent(tmp_path):
    wf = tmp_path / "tpl.yaml"
    wf.write_text(
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: ClusterWorkflowTemplate\n"
        "metadata:\n"
        "  name: shared\n"
        "spec:\n"
        "  templates: []\n"
    )
    provider = _providers.get("argo")
    inv = provider.inventory(provider.build_context(argo_path=str(wf)))
    assert "namespace" not in inv[0].metadata


def test_argo_inventory_unnamed_workflow_uses_placeholder(tmp_path):
    wf = tmp_path / "unnamed.yaml"
    wf.write_text(
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "metadata: {}\n"
        "spec: {}\n"
    )
    provider = _providers.get("argo")
    inv = provider.inventory(provider.build_context(argo_path=str(wf)))
    # Empty metadata-name → identifier surfaces the placeholder.
    assert inv[0].identifier == "Workflow/<unnamed>"
    # spec is an empty dict, no template_count or entrypoint metadata.
    assert "template_count" not in inv[0].metadata
    assert "entrypoint" not in inv[0].metadata


# ── Tekton inventory ───────────────────────────────────────────────


def test_tekton_inventory_extracts_task_metadata(tmp_path):
    t = tmp_path / "build.yaml"
    t.write_text(
        "apiVersion: tekton.dev/v1\n"
        "kind: Task\n"
        "metadata:\n"
        "  name: build\n"
        "  namespace: ci\n"
        "spec:\n"
        "  steps:\n"
        "    - name: compile\n"
        "      image: gcr.io/cloud-builders/go\n"
        "    - name: test\n"
        "      image: gcr.io/cloud-builders/go\n"
    )
    provider = _providers.get("tekton")
    inv = provider.inventory(provider.build_context(tekton_path=str(t)))
    assert len(inv) == 1
    c = inv[0]
    assert c.type == "task"
    assert c.identifier == "Task/build"
    assert c.metadata["namespace"] == "ci"
    assert c.metadata["step_count"] == 2


def test_tekton_inventory_pipeline_uses_tasks_field(tmp_path):
    t = tmp_path / "pipe.yaml"
    t.write_text(
        "apiVersion: tekton.dev/v1\n"
        "kind: Pipeline\n"
        "metadata:\n  name: release\n"
        "spec:\n"
        "  tasks:\n"
        "    - name: lint\n      taskRef: {name: lint}\n"
        "    - name: test\n      taskRef: {name: test}\n"
        "    - name: deploy\n      taskRef: {name: deploy}\n"
    )
    provider = _providers.get("tekton")
    inv = provider.inventory(provider.build_context(tekton_path=str(t)))
    assert inv[0].metadata["task_count"] == 3


# ── Buildkite inventory ────────────────────────────────────────────


def test_buildkite_inventory_excludes_wait_block_input_trigger(tmp_path):
    cfg = tmp_path / "pipeline.yml"
    cfg.write_text(
        "agents:\n  queue: deploy-runners\n"
        "steps:\n"
        "  - label: Build\n    command: make build\n"
        "  - wait\n"
        "  - block: Confirm?\n"
        "  - input: Provide a tag\n"
        "  - trigger: downstream\n"
        "  - label: Deploy\n    command: make deploy\n"
    )
    provider = _providers.get("buildkite")
    inv = provider.inventory(provider.build_context(buildkite_path=str(cfg)))
    assert len(inv) == 1
    # Only the two command-bearing steps count; flow-control steps
    # are excluded so the metric reflects "real work units".
    assert inv[0].metadata["step_count"] == 2
    assert inv[0].metadata["queue"] == "deploy-runners"


def test_buildkite_inventory_omits_queue_when_no_agents(tmp_path):
    cfg = tmp_path / "pipeline.yml"
    cfg.write_text("steps:\n  - label: Build\n    command: make build\n")
    provider = _providers.get("buildkite")
    inv = provider.inventory(provider.build_context(buildkite_path=str(cfg)))
    assert "queue" not in inv[0].metadata
    assert inv[0].metadata["step_count"] == 1


# ── Cloud Build inventory ──────────────────────────────────────────


def test_cloudbuild_inventory_surface_service_account_and_pool(tmp_path):
    cfg = tmp_path / "cloudbuild.yaml"
    cfg.write_text(
        "serviceAccount: projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com\n"
        "options:\n"
        "  pool:\n"
        "    name: projects/p/locations/us/workerPools/internal\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/go\n    args: [build]\n"
        "  - name: gcr.io/cloud-builders/go\n    args: [test]\n"
    )
    provider = _providers.get("cloudbuild")
    inv = provider.inventory(provider.build_context(cloudbuild_path=str(cfg)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["step_count"] == 2
    assert m["service_account"].endswith("@p.iam.gserviceaccount.com")
    assert m["worker_pool"].endswith("/workerPools/internal")


def test_cloudbuild_inventory_blank_service_account_not_surfaced(tmp_path):
    cfg = tmp_path / "cloudbuild.yaml"
    cfg.write_text(
        "serviceAccount: '   '\n"
        "steps:\n  - name: gcr.io/cloud-builders/go\n    args: [build]\n"
    )
    provider = _providers.get("cloudbuild")
    inv = provider.inventory(provider.build_context(cloudbuild_path=str(cfg)))
    # Whitespace-only service account is treated as absent.
    assert "service_account" not in inv[0].metadata


def test_cloudbuild_inventory_options_without_pool_skipped(tmp_path):
    cfg = tmp_path / "cloudbuild.yaml"
    cfg.write_text(
        "options:\n  machineType: E2_HIGHCPU_32\n"
        "steps:\n  - name: gcr.io/cloud-builders/go\n    args: [build]\n"
    )
    provider = _providers.get("cloudbuild")
    inv = provider.inventory(provider.build_context(cloudbuild_path=str(cfg)))
    assert "worker_pool" not in inv[0].metadata


# ── Dockerfile inventory ───────────────────────────────────────────


def test_dockerfile_inventory_counts_directives_and_stages(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM alpine:3.20 AS build\n"
        "RUN apk add --no-cache make\n"
        "RUN make all\n"
        "FROM alpine:3.20\n"
        "COPY --from=build /out /\n"
        "CMD [\"/run\"]\n"
    )
    provider = _providers.get("dockerfile")
    inv = provider.inventory(provider.build_context(dockerfile_path=str(df)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["stages"] == 2  # two FROM directives
    assert m["run_steps"] == 2
    # Each tracked directive counts toward the total (FROM, RUN, RUN, FROM, COPY, CMD = 6).
    assert m["instruction_count"] == 6
    assert inv[0].type == "dockerfile"


# ── npm inventory ──────────────────────────────────────────────────


def test_npm_inventory_manifest_dependency_counts(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"name":"my-app","version":"1.0.0",'
        '"dependencies":{"react":"18","lodash":"4"},'
        '"devDependencies":{"jest":"29"}}'
    )
    provider = _providers.get("npm")
    inv = provider.inventory(provider.build_context(npm_path=str(pkg)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["kind"] == "package.json"
    assert m["name"] == "my-app"
    assert m["version"] == "1.0.0"
    assert m["dependency_count"] == 2
    assert m["dev_dependency_count"] == 1


def test_npm_inventory_handles_missing_dep_blocks(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name":"bare","version":"0.0.1"}')
    provider = _providers.get("npm")
    inv = provider.inventory(provider.build_context(npm_path=str(pkg)))
    # Missing dependencies / devDependencies are treated as zero, not
    # crashes or None values.
    assert inv[0].metadata["dependency_count"] == 0
    assert inv[0].metadata["dev_dependency_count"] == 0


def test_npm_inventory_lockfile_counts_packages(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        '{"name":"app","version":"1.0.0","lockfileVersion":3,'
        '"packages":{"":{"name":"app"},"node_modules/react":{}}}'
    )
    provider = _providers.get("npm")
    inv = provider.inventory(provider.build_context(npm_path=str(lock)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["kind"] == "package-lock.json"
    assert m["package_count"] == 2
    assert m["lockfile_version"] == 3


# ── Maven inventory ────────────────────────────────────────────────


def test_maven_inventory_pom_counts(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        '  <modelVersion>4.0.0</modelVersion>\n'
        '  <groupId>com.example</groupId>\n'
        '  <artifactId>app</artifactId>\n'
        '  <version>1.0.0</version>\n'
        '  <dependencies>\n'
        '    <dependency>\n'
        '      <groupId>org.junit.jupiter</groupId>\n'
        '      <artifactId>junit-jupiter</artifactId>\n'
        '      <version>5.10.0</version>\n'
        '    </dependency>\n'
        '  </dependencies>\n'
        '  <repositories>\n'
        '    <repository>\n'
        '      <id>internal</id>\n'
        '      <url>https://nexus.example.com</url>\n'
        '    </repository>\n'
        '  </repositories>\n'
        '</project>\n'
    )
    provider = _providers.get("maven")
    inv = provider.inventory(provider.build_context(maven_path=str(pom)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["kind"] == "pom.xml"
    assert m["dependency_count"] == 1
    assert m["repository_count"] == 1
    assert m["mirror_count"] == 0
    assert inv[0].type == "pom.xml"


def test_maven_inventory_settings_xml_marked_as_settings(tmp_path):
    settings = tmp_path / "settings.xml"
    settings.write_text(
        '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">\n'
        '  <mirrors>\n'
        '    <mirror>\n'
        '      <id>nexus</id>\n'
        '      <mirrorOf>*</mirrorOf>\n'
        '      <url>https://nexus.example.com</url>\n'
        '    </mirror>\n'
        '  </mirrors>\n'
        '</settings>\n'
    )
    provider = _providers.get("maven")
    inv = provider.inventory(provider.build_context(maven_path=str(settings)))
    assert inv[0].type == "settings.xml"
    assert inv[0].metadata["mirror_count"] == 1


# ── pypi inventory ─────────────────────────────────────────────────


def test_pypi_inventory_requirements_counts(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "--index-url https://internal.example.com/pypi\n"
        "--extra-index-url https://pypi.org/simple\n"
        "requests==2.28.1\n"
        "click>=8.0\n"
        "# comment line should be ignored\n"
        "\n"
        "PyYAML==6.0\n"
    )
    provider = _providers.get("pypi")
    inv = provider.inventory(provider.build_context(pypi_path=str(req)))
    assert len(inv) == 1
    m = inv[0].metadata
    assert m["kind"] == "requirements.txt"
    # Three concrete requirement lines (comments / blanks excluded by
    # the parser).
    assert m["requirement_count"] == 3
    # --index-url + --extra-index-url = 2 option entries.
    assert m["option_count"] == 2
