"""Per-provider source-path resolution for the ``scan`` command.

``scan()`` exposes one ``--<provider>-path`` flag per provider;
:func:`_resolve_provider_paths` auto-detects / validates each selected
provider's path (via :func:`_resolve_provider_path`) and bundles them
into a :class:`_ScanPaths` so the scanner-kwargs construction reads one
object instead of ~30 loose locals. Extracted from ``cli.py`` to keep
that module focused on argument wiring; this cluster depends only on
``os`` / ``click`` and is re-imported into ``cli`` so the ``scan()`` call
site is unchanged.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import click


def _resolve_provider_path(
    provider_lc: str,
    *,
    flag: str,
    value: str | None,
    candidates: tuple[str, ...] = (),
    candidate_kind: str = "file",
    validate_kind: str = "exists",
    detect_label: str = "",
    not_found_label: str = "",
) -> str:
    """Auto-detect, validate, and return a per-provider input path.

    Replaces the per-provider elif ladder that ``main()`` used to
    carry. Cloudformation and helm have edge cases (template-folder
    detection, ``--helm-values`` validation) so they stay inline;
    every other provider's contract is exactly:

      1. If the user didn't pass ``--<flag>``, walk *candidates*
         and pick the first one that exists. ``candidate_kind`` is
         ``file`` for canonical files (``.gitlab-ci.yml``) or
         ``dir`` for canonical directories (``.github/workflows``).
      2. If still empty, raise ``UsageError`` with a hint that names
         the canonical files we looked for (*detect_label*).
      3. Validate that the resolved path exists. ``validate_kind``
         is ``exists`` (default; file or dir), ``file``, or ``dir``.
         ``not_found_label`` ("directory" / "path") inserts a noun
         into the error message when the validation kind is stricter
         than ``exists``.
    """
    if not value:
        check = os.path.isdir if candidate_kind == "dir" else os.path.isfile
        for cand in candidates:
            if check(cand):
                value = cand
                click.echo(f"[auto] using --{flag} {value}", err=True)
                break
    if not value:
        suffix = (
            f" (no {detect_label} found in the current directory)."
            if detect_label else "."
        )
        raise click.UsageError(
            f"--{flag} PATH is required when --pipeline {provider_lc}{suffix}"
        )
    validators = {
        "exists": os.path.exists,
        "file": os.path.isfile,
        "dir": os.path.isdir,
    }
    if not validators[validate_kind](value):
        kind_word = (not_found_label + " ") if not_found_label else ""
        raise click.UsageError(
            f"--{flag} {kind_word}not found: {value}"
        )
    return value


@dataclass
class _ScanPaths:
    """The per-provider source paths after auto-detect / validation.

    ``scan()`` carries one ``--<provider>-path`` flag per provider;
    :func:`_resolve_provider_paths` resolves each and returns them
    bundled here so the scanner-kwargs construction reads one object
    instead of ~30 loose locals.
    """
    tf_plan: str | None = None
    tf_source: str | None = None
    gha_path: str | None = None
    gitea_path: str | None = None
    gitlab_path: str | None = None
    bitbucket_path: str | None = None
    azure_path: str | None = None
    jenkinsfile_path: str | None = None
    circleci_path: str | None = None
    cfn_template: str | None = None
    cloudbuild_path: str | None = None
    buildkite_path: str | None = None
    tekton_path: str | None = None
    argo_path: str | None = None
    argocd_path: str | None = None
    dockerfile_path: str | None = None
    k8s_path: str | None = None
    helm_path: str | None = None
    oci_manifest: str | None = None
    drone_path: str | None = None
    harness_path: str | None = None
    npm_path: str | None = None
    pypi_path: str | None = None
    maven_path: str | None = None
    nuget_path: str | None = None
    gomod_path: str | None = None
    cargo_path: str | None = None
    composer_path: str | None = None
    rubygems_path: str | None = None
    pulumi_path: str | None = None


@dataclass(frozen=True)
class ProviderPathArgs:
    """The raw ``--<provider>-path`` flag values as ``scan()`` receives them.

    ``scan()``'s signature is fixed by Click (one option binds to one
    parameter), so these ~30 path flags arrive as loose locals. Bundling
    them into one frozen object lets :func:`_resolve_provider_paths` (and
    any future consumer) take a single typed argument instead of a
    31-keyword call, and gives the group a documented name. The *resolved*
    counterpart, after auto-detect / validation, is :class:`_ScanPaths`.

    Every field defaults to ``None`` / ``()`` so a caller constructs it
    with only the flags it has, keyword-style; the field names match the
    ``scan()`` parameters and the ``_ScanPaths`` fields one-to-one.
    """
    tf_plan: str | None = None
    tf_source: str | None = None
    gha_path: str | None = None
    gitea_path: str | None = None
    gitlab_path: str | None = None
    bitbucket_path: str | None = None
    azure_path: str | None = None
    jenkinsfile_path: str | None = None
    circleci_path: str | None = None
    cfn_template: str | None = None
    cloudbuild_path: str | None = None
    buildkite_path: str | None = None
    tekton_path: str | None = None
    argo_path: str | None = None
    argocd_path: str | None = None
    dockerfile_path: str | None = None
    k8s_path: str | None = None
    helm_path: str | None = None
    oci_manifest: str | None = None
    drone_path: str | None = None
    harness_path: str | None = None
    npm_path: str | None = None
    pypi_path: str | None = None
    maven_path: str | None = None
    nuget_path: str | None = None
    gomod_path: str | None = None
    cargo_path: str | None = None
    composer_path: str | None = None
    rubygems_path: str | None = None
    pulumi_path: str | None = None
    helm_values: tuple[str, ...] = ()


def _resolve_provider_paths(
    pipelines_to_resolve: list[str],
    path_args: ProviderPathArgs,
) -> _ScanPaths:
    """Resolve / auto-detect each selected provider's source path.

    Runs once per provider in *pipelines_to_resolve* (one entry in
    single-pipeline mode, the full list in multi-pipeline mode),
    auto-detecting a canonical path when the flag was omitted and raising
    ``click.UsageError`` on a missing or invalid one. Returns the
    resolved paths bundled for the scanner kwargs.

    *path_args* carries the raw ``--<provider>-path`` flag values; it is
    unpacked into the working locals the resolution loop reassigns, so the
    per-provider logic below reads exactly as it did when this took one
    keyword argument per flag.
    """
    tf_plan = path_args.tf_plan
    tf_source = path_args.tf_source
    gha_path = path_args.gha_path
    gitea_path = path_args.gitea_path
    gitlab_path = path_args.gitlab_path
    bitbucket_path = path_args.bitbucket_path
    azure_path = path_args.azure_path
    jenkinsfile_path = path_args.jenkinsfile_path
    circleci_path = path_args.circleci_path
    cfn_template = path_args.cfn_template
    cloudbuild_path = path_args.cloudbuild_path
    buildkite_path = path_args.buildkite_path
    tekton_path = path_args.tekton_path
    argo_path = path_args.argo_path
    argocd_path = path_args.argocd_path
    dockerfile_path = path_args.dockerfile_path
    k8s_path = path_args.k8s_path
    helm_path = path_args.helm_path
    oci_manifest = path_args.oci_manifest
    drone_path = path_args.drone_path
    harness_path = path_args.harness_path
    npm_path = path_args.npm_path
    pypi_path = path_args.pypi_path
    maven_path = path_args.maven_path
    nuget_path = path_args.nuget_path
    gomod_path = path_args.gomod_path
    cargo_path = path_args.cargo_path
    composer_path = path_args.composer_path
    rubygems_path = path_args.rubygems_path
    pulumi_path = path_args.pulumi_path
    helm_values = path_args.helm_values

    for pipeline_lc in pipelines_to_resolve:
        if pipeline_lc == "terraform":
            if tf_plan and tf_source:
                raise click.UsageError(
                    "--tf-plan and --tf-source are mutually exclusive."
                )
            if tf_plan:
                tf_plan = _resolve_provider_path(
                    "terraform", flag="tf-plan", value=tf_plan,
                    validate_kind="file", not_found_label="path",
                )
            elif tf_source:
                tf_source = _resolve_provider_path(
                    "terraform", flag="tf-source", value=tf_source,
                    validate_kind="dir", not_found_label="directory",
                )
            elif os.path.isfile("main.tf"):
                tf_source = "."
                click.echo(
                    "[auto] using --tf-source . (main.tf detected)",
                    err=True,
                )
        elif pipeline_lc == "github":
            gha_path = _resolve_provider_path(
                "github", flag="gha-path", value=gha_path,
                candidates=(".github/workflows",), candidate_kind="dir",
                validate_kind="dir", detect_label=".github/workflows",
                not_found_label="directory",
            )
        elif pipeline_lc == "gitea":
            gitea_path = _resolve_provider_path(
                "gitea", flag="gitea-path", value=gitea_path,
                candidates=(".gitea/workflows", ".forgejo/workflows"),
                candidate_kind="dir",
                validate_kind="dir",
                detect_label=".gitea/workflows or .forgejo/workflows",
                not_found_label="directory",
            )
        elif pipeline_lc == "gitlab":
            gitlab_path = _resolve_provider_path(
                "gitlab", flag="gitlab-path", value=gitlab_path,
                candidates=(".gitlab-ci.yml",),
                detect_label=".gitlab-ci.yml",
            )
        elif pipeline_lc == "bitbucket":
            bitbucket_path = _resolve_provider_path(
                "bitbucket", flag="bitbucket-path", value=bitbucket_path,
                candidates=("bitbucket-pipelines.yml",),
                detect_label="bitbucket-pipelines.yml",
            )
        elif pipeline_lc == "azure":
            azure_path = _resolve_provider_path(
                "azure", flag="azure-path", value=azure_path,
                candidates=("azure-pipelines.yml",),
                detect_label="azure-pipelines.yml",
            )
        elif pipeline_lc == "jenkins":
            jenkinsfile_path = _resolve_provider_path(
                "jenkins", flag="jenkinsfile-path", value=jenkinsfile_path,
                candidates=("Jenkinsfile",),
                detect_label="Jenkinsfile",
            )
        elif pipeline_lc == "circleci":
            circleci_path = _resolve_provider_path(
                "circleci", flag="circleci-path", value=circleci_path,
                candidates=(".circleci/config.yml",),
                detect_label=".circleci/config.yml",
            )
        elif pipeline_lc == "cloudformation":
            if not cfn_template:
                for _candidate in (
                    "template.yml", "template.yaml", "template.json",
                    "cloudformation.yml", "cloudformation.yaml",
                    "cfn.yml", "cfn.yaml",
                ):
                    if os.path.isfile(_candidate):
                        cfn_template = _candidate
                        click.echo(
                            f"[auto] using --cfn-template {cfn_template}",
                            err=True,
                        )
                        break
            if not cfn_template:
                raise click.UsageError(
                    "--cfn-template PATH is required when --pipeline "
                    "cloudformation (no template.yml / template.json / "
                    "cloudformation.yml / cfn.yaml found in the current "
                    "directory)."
                )
            if not os.path.exists(cfn_template):
                raise click.UsageError(
                    f"--cfn-template not found: {cfn_template}"
                )
            # Distinguish "directory but no templates" from "file not found" —
            # the former is a common mistake when someone points the flag at
            # their project root instead of an infrastructure subdirectory.
            if os.path.isdir(cfn_template):
                _exts = (".yml", ".yaml", ".json", ".template")
                has_templates = any(
                    _ent.is_file() and _ent.name.lower().endswith(_exts)
                    for _ent in os.scandir(cfn_template)
                )
                if not has_templates:
                    raise click.UsageError(
                        f"--cfn-template directory {cfn_template!r} contains "
                        f"no .yml / .yaml / .json / .template files."
                    )
        elif pipeline_lc == "cloudbuild":
            cloudbuild_path = _resolve_provider_path(
                "cloudbuild", flag="cloudbuild-path", value=cloudbuild_path,
                candidates=("cloudbuild.yaml", "cloudbuild.yml"),
                detect_label="cloudbuild.yaml/cloudbuild.yml",
            )
        elif pipeline_lc == "buildkite":
            buildkite_path = _resolve_provider_path(
                "buildkite", flag="buildkite-path", value=buildkite_path,
                candidates=(".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"),
                detect_label=".buildkite/pipeline.yml",
            )
        elif pipeline_lc == "tekton":
            tekton_path = _resolve_provider_path(
                "tekton", flag="tekton-path", value=tekton_path,
            )
        elif pipeline_lc == "argo":
            argo_path = _resolve_provider_path(
                "argo", flag="argo-path", value=argo_path,
            )
        elif pipeline_lc == "argocd":
            argocd_path = _resolve_provider_path(
                "argocd", flag="argocd-path", value=argocd_path,
            )
        elif pipeline_lc == "dockerfile":
            dockerfile_path = _resolve_provider_path(
                "dockerfile", flag="dockerfile-path", value=dockerfile_path,
                candidates=("Dockerfile", "Containerfile"),
                detect_label="Dockerfile/Containerfile",
            )
        elif pipeline_lc == "kubernetes":
            k8s_path = _resolve_provider_path(
                "kubernetes", flag="k8s-path", value=k8s_path,
                candidates=("kubernetes", "k8s", "manifests"),
                candidate_kind="dir",
                detect_label="kubernetes/, k8s/, or manifests/ directory",
            )
        elif pipeline_lc == "helm":
            if not helm_path:
                if os.path.isfile("Chart.yaml"):
                    helm_path = "."
                    click.echo("[auto] using --helm-path .", err=True)
                elif os.path.isdir("charts"):
                    helm_path = "charts"
                    click.echo("[auto] using --helm-path charts", err=True)
            if not helm_path:
                raise click.UsageError(
                    "--helm-path PATH is required when --pipeline helm "
                    "(no Chart.yaml or charts/ directory found in cwd)."
                )
            if not os.path.exists(helm_path):
                raise click.UsageError(
                    f"--helm-path not found: {helm_path}"
                )
            for vf in helm_values:
                if not os.path.isfile(vf):
                    raise click.UsageError(
                        f"--helm-values not found: {vf}"
                    )
        elif pipeline_lc == "oci":
            oci_manifest = _resolve_provider_path(
                "oci", flag="oci-manifest", value=oci_manifest,
                candidates=("index.json",),
                detect_label="index.json",
            )
        elif pipeline_lc == "drone":
            drone_path = _resolve_provider_path(
                "drone", flag="drone-path", value=drone_path,
                candidates=(".drone.yml", ".drone.yaml"),
                detect_label=".drone.yml/.drone.yaml",
            )
        elif pipeline_lc == "harness":
            harness_path = _resolve_provider_path(
                "harness", flag="harness-path", value=harness_path,
                candidates=(".harness",),
                detect_label=".harness/",
            )
        elif pipeline_lc == "npm":
            npm_path = _resolve_provider_path(
                "npm", flag="npm-path", value=npm_path,
                candidates=("package.json", "package-lock.json"),
                detect_label="package.json/package-lock.json",
            )
        elif pipeline_lc == "pypi":
            pypi_path = _resolve_provider_path(
                "pypi", flag="pypi-path", value=pypi_path,
                candidates=("requirements.txt",),
                detect_label="requirements.txt",
            )
        elif pipeline_lc == "maven":
            maven_path = _resolve_provider_path(
                "maven", flag="maven-path", value=maven_path,
                candidates=("pom.xml",),
                detect_label="pom.xml",
            )
        elif pipeline_lc == "nuget":
            nuget_path = _resolve_provider_path(
                "nuget", flag="nuget-path", value=nuget_path,
                candidates=("Directory.Packages.props",),
                detect_label="Directory.Packages.props",
            )
        elif pipeline_lc == "gomod":
            gomod_path = _resolve_provider_path(
                "gomod", flag="gomod-path", value=gomod_path,
                candidates=("go.mod",),
                detect_label="go.mod",
            )
        elif pipeline_lc == "cargo":
            cargo_path = _resolve_provider_path(
                "cargo", flag="cargo-path", value=cargo_path,
                candidates=("Cargo.toml",),
                detect_label="Cargo.toml",
            )
        elif pipeline_lc == "composer":
            composer_path = _resolve_provider_path(
                "composer", flag="composer-path",
                value=composer_path,
                candidates=("composer.json",),
                detect_label="composer.json",
            )
        elif pipeline_lc == "rubygems":
            rubygems_path = _resolve_provider_path(
                "rubygems", flag="rubygems-path",
                value=rubygems_path,
                candidates=("Gemfile",),
                detect_label="Gemfile",
            )
        elif pipeline_lc == "pulumi":
            pulumi_path = _resolve_provider_path(
                "pulumi", flag="pulumi-path", value=pulumi_path,
                candidates=("Pulumi.yaml",),
                detect_label="Pulumi.yaml",
            )
    return _ScanPaths(
        tf_plan=tf_plan,
        tf_source=tf_source,
        gha_path=gha_path,
        gitea_path=gitea_path,
        gitlab_path=gitlab_path,
        bitbucket_path=bitbucket_path,
        azure_path=azure_path,
        jenkinsfile_path=jenkinsfile_path,
        circleci_path=circleci_path,
        cfn_template=cfn_template,
        cloudbuild_path=cloudbuild_path,
        buildkite_path=buildkite_path,
        tekton_path=tekton_path,
        argo_path=argo_path,
        argocd_path=argocd_path,
        dockerfile_path=dockerfile_path,
        k8s_path=k8s_path,
        helm_path=helm_path,
        oci_manifest=oci_manifest,
        drone_path=drone_path,
        harness_path=harness_path,
        npm_path=npm_path,
        pypi_path=pypi_path,
        maven_path=maven_path,
        nuget_path=nuget_path,
        gomod_path=gomod_path,
        cargo_path=cargo_path,
        composer_path=composer_path,
        rubygems_path=rubygems_path,
        pulumi_path=pulumi_path,
    )
