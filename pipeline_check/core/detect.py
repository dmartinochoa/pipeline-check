"""Provider auto-detection from the working directory.

Maps each provider's canonical marker files / directories to its name so
an entry point can pick a provider (or the full set of providers) without
the user naming one. Kept free of Click and CLI state so the CLI, the LSP
server, and the MCP server can share one detector instead of each
re-deriving the table (the LSP currently carries its own copy).
"""
from __future__ import annotations

import os

# Provider detection table. Each entry maps a provider name to the list
# of cwd-relative paths whose presence signals "this provider should
# scan here". File entries use ``os.path.isfile``; directory entries use
# ``os.path.isdir``. Iterated by both :func:`detect_pipeline_from_cwd`
# (first-match-wins single-provider detection) and
# :func:`detect_all_pipelines_from_cwd` (multi-provider walk that
# returns every provider whose canonical path is present).
#
# Order matters: helm before kubernetes because a ``Chart.yaml`` at
# the repo root is an unambiguous signal, whereas the k8s indicators
# (``kubernetes/``, ``k8s/``, ``manifests/``) are generic directory
# names that helm charts often use too. Multi-detect drops the
# ambiguous-k8s case when helm already matched (see below).
PROVIDER_DETECT_FILES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    # (provider, files, directories)
    ("github", (), (".github/workflows",)),
    ("gitea", (), (".gitea/workflows", ".forgejo/workflows")),
    ("gitlab", (".gitlab-ci.yml",), ()),
    ("circleci", (".circleci/config.yml",), ()),
    ("jenkins", ("Jenkinsfile",), ()),
    ("azure", ("azure-pipelines.yml",), ()),
    ("bitbucket", ("bitbucket-pipelines.yml",), ()),
    ("cloudbuild", ("cloudbuild.yaml", "cloudbuild.yml"), ()),
    ("buildkite", (".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"), ()),
    ("drone", (".drone.yml", ".drone.yaml"), ()),
    ("harness", (), (".harness",)),
    ("dockerfile", ("Dockerfile", "Containerfile"), ()),
    ("npm", ("package.json", "package-lock.json"), ()),
    ("pypi", ("requirements.txt",), ()),
    ("maven", ("pom.xml",), ()),
    ("nuget", ("Directory.Packages.props",), ()),
    ("gomod", ("go.mod",), ()),
    ("cargo", ("Cargo.toml",), ()),
    ("composer", ("composer.json",), ()),
    ("rubygems", ("Gemfile",), ()),
    ("pulumi", ("Pulumi.yaml",), ()),
    ("terraform", ("main.tf", "providers.tf", "versions.tf", "terraform.tf"), ()),
    (
        "cloudformation",
        (
            "template.yml", "template.yaml", "template.json",
            "cloudformation.yml", "cloudformation.yaml",
            "cfn.yml", "cfn.yaml",
        ),
        (),
    ),
    # OCI deliberately omitted from auto-detect: ``index.json`` is too
    # generic a filename to promote on presence alone (Backstage,
    # Sphinx, and various Node tooling produce unrelated index.json
    # files at repo roots). ``--pipeline oci`` still auto-resolves
    # ``index.json`` when explicitly selected; multi-provider runs
    # that want OCI in scope use ``--pipelines github,oci``.
    ("helm", ("Chart.yaml",), ()),
    # Developer-environment auto-execution configs. Listed late so a
    # repo that also ships a real CI / registry manifest is detected as
    # that provider first; multi-provider auto-detect still adds devenv.
    (
        "devenv",
        (
            ".vscode/tasks.json",
            ".devcontainer.json",
            ".devcontainer/devcontainer.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        ),
        (),
    ),
    ("kubernetes", (), ("kubernetes", "k8s", "manifests")),
)


def provider_present(files: tuple[str, ...], dirs: tuple[str, ...]) -> bool:
    """True when any marker file or directory exists at cwd."""
    return any(os.path.isfile(f) for f in files) or any(os.path.isdir(d) for d in dirs)


def detect_pipeline_from_cwd() -> str | None:
    """Return the best-guess pipeline name based on files present at cwd.

    First match wins. Returns None when nothing recognizable is found;
    the caller then falls back to ``aws`` (preserves prior default).
    """
    for name, files, dirs in PROVIDER_DETECT_FILES:
        if provider_present(files, dirs):
            return name
    return None


def detect_all_pipelines_from_cwd() -> list[str]:
    """Return every provider whose canonical path is present at cwd.

    Used by the no-args / ``--pipeline auto`` flow to switch into
    multi-provider mode automatically when a repo carries more than
    one pipeline-shape file (e.g. ``.github/workflows`` and a
    ``Dockerfile``). Order follows :data:`PROVIDER_DETECT_FILES` so
    multi-mode runs sub-scanners in a stable, repeatable sequence.

    Helm / Kubernetes disambiguation: a Helm chart's templates often
    sit under ``charts/`` next to a ``Chart.yaml``, so when both helm
    and kubernetes match at cwd, kubernetes is dropped to avoid
    rendering the same charts twice (helm renders templates and
    feeds them to the K8s rule pack already).
    """
    detected: list[str] = []
    for name, files, dirs in PROVIDER_DETECT_FILES:
        if provider_present(files, dirs):
            detected.append(name)
    if "helm" in detected and "kubernetes" in detected:
        detected.remove("kubernetes")
    return detected
