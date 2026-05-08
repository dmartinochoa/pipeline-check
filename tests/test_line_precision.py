"""Cross-provider line-precision contract.

For each retrofitted rule, scan the omnibus insecure fixture and
assert the rule emits at least one ``Location`` with a non-``None``
``start_line``. This is the regression guard: if a future loader
change drops line markers, every retrofitted rule trips here.

Adding a new rule with line precision: append it to ``CASES`` below.
The fixture file must already exist and trigger the rule.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.scanner import Scanner

FIXTURES = Path(__file__).parent / "fixtures" / "workflows"


# (provider, scanner-kwarg, fixture-path, check_id)
CASES: list[tuple[str, str, Path, str]] = [
    ("buildkite", "buildkite_path",
     FIXTURES / "buildkite" / "insecure-pipeline.yml", "BK-001"),
    ("cloudbuild", "cloudbuild_path",
     FIXTURES / "cloudbuild" / "insecure-cloudbuild.yaml", "GCB-001"),
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-001"),
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-025"),
    ("gitlab", "gitlab_path",
     FIXTURES / "gitlab" / "insecure.gitlab-ci.yml", "GL-001"),
    ("bitbucket", "bitbucket_path",
     FIXTURES / "bitbucket" / "insecure-bitbucket-pipelines.yml", "BB-001"),
    ("azure", "azure_path",
     FIXTURES / "azure" / "insecure-azure-pipelines.yml", "ADO-001"),
    ("circleci", "circleci_path",
     FIXTURES / "circleci" / "insecure-config.yml", "CC-003"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-001"),
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-001"),
    ("tekton", "tekton_path",
     FIXTURES / "tekton" / "insecure-tekton.yaml", "TKN-001"),
    ("argo", "argo_path",
     FIXTURES / "argo" / "insecure-argo.yaml", "ARGO-001"),
    # Round-7 retrofits — high-fire rules whose offending line was
    # previously inferred via the regex best-effort fallback.
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-005"),
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-013"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-002"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-004"),
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-002"),
    # Round-8 batch — secret literals, RBAC binding, ENV credentials,
    # script injection (GitLab + GHA), Jenkins library pinning.
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-018"),
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-020"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-006"),
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-003"),
    ("gitlab", "gitlab_path",
     FIXTURES / "gitlab" / "insecure.gitlab-ci.yml", "GL-002"),
    ("jenkins", "jenkinsfile_path",
     FIXTURES / "jenkins" / "Jenkinsfile.insecure", "JF-001"),
    # Round-12 batch — privileged docker, wildcard RBAC, curl-pipe.
    # GHA-017 / DF-008 anchor at the offending step / RUN line;
    # K8S-021 anchors on the offending rules entry; CC-016 / GL-016
    # anchor on the offending job (the cross-job blob scan stays
    # for legacy coverage but the per-job rescan recovers the line).
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-017"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-008"),
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-021"),
    ("circleci", "circleci_path",
     FIXTURES / "circleci" / "insecure-config.yml", "CC-016"),
    ("gitlab", "gitlab_path",
     FIXTURES / "gitlab" / "insecure.gitlab-ci.yml", "GL-016"),
    # Round-17 batch — issue_comment trigger, LB source ranges,
    # shell-eval, two more script-injection rules.
    ("github", "gha_path",
     FIXTURES / "github" / "insecure-release.yml", "GHA-013"),
    ("kubernetes", "k8s_path",
     FIXTURES / "k8s" / "insecure.yaml", "K8S-026"),
    ("dockerfile", "dockerfile_path",
     FIXTURES / "dockerfile" / "insecure-Dockerfile", "DF-005"),
    ("circleci", "circleci_path",
     FIXTURES / "circleci" / "insecure-config.yml", "CC-002"),
    ("bitbucket", "bitbucket_path",
     FIXTURES / "bitbucket" / "insecure-bitbucket-pipelines.yml", "BB-002"),
]


@pytest.mark.parametrize("provider,kw,fixture,check_id", CASES)
def test_rule_emits_line_precise_location(
    provider: str, kw: str, fixture: Path, check_id: str,
) -> None:
    scanner = Scanner(pipeline=provider, **{kw: str(fixture)})
    findings = scanner.run()
    matching = [f for f in findings if f.check_id == check_id and not f.passed]
    assert matching, (
        f"{check_id} did not fire on {fixture.name}; cannot assert "
        f"line precision"
    )
    locations = matching[0].locations
    assert locations, (
        f"{check_id} fired but emitted no structured locations — the "
        f"rule was retrofitted to set ``Finding.locations`` but isn't "
        f"populating it. Check the loader and the rule body."
    )
    primary = locations[0]
    assert primary.start_line is not None and primary.start_line > 0, (
        f"{check_id} emitted a Location but ``start_line`` is missing "
        f"or non-positive ({primary.start_line!r}). The line-aware "
        f"loader probably isn't wired in for this provider."
    )
