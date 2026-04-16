"""Per-check end-to-end tests using realistic snippets.

For every workflow-provider check (47 total: 8 GHA + 9 GL + 9 BB + 9
ADO + 12 JF) this module exercises:

  1. an UNSAFE snippet sourced from real-world anti-patterns, and
     asserts the targeted check fires AND carries the expected OWASP
     and ESF (where mapped) ControlRefs.
  2. a SAFE snippet — usually the same shape with the fix applied —
     and asserts the targeted check passes.

Other checks may pass or fail on either snippet; the per-check tests
only assert behaviour for the targeted check_id. The broader sweep
in ``test_workflow_fixtures.py`` covers cross-check coordination on
the larger fixtures.

Adding a check
--------------
1. Append a ``CheckCase`` to ``CASES`` below.
2. The unsafe snippet must trigger the targeted check.
3. The safe snippet must NOT trigger the targeted check.
4. ``expected_owasp`` is the primary OWASP CICD-SEC control. Add
   ``expected_esf`` if the check has an ESF mapping.

The provider context loader is selected automatically from the
check ID prefix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks
from pipeline_check.core.checks.base import Finding
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks
from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks
from pipeline_check.core import standards as standards_mod


# ──────────────────────────────────────────────────────────────────────
# Test harness
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CheckCase:
    check_id: str
    unsafe: str
    safe: str
    expected_owasp: str
    expected_esf: tuple[str, ...] = field(default_factory=tuple)


_PROVIDER_BY_PREFIX: dict[str, tuple[Any, Any, str]] = {
    # prefix -> (context_class, check_class, fixture filename)
    "GHA": (GitHubContext, WorkflowChecks, "wf.yml"),
    "GL":  (GitLabContext, GitLabPipelineChecks, ".gitlab-ci.yml"),
    "BB":  (BitbucketContext, BitbucketPipelineChecks, "bitbucket-pipelines.yml"),
    "ADO": (AzureContext, AzurePipelineChecks, "azure-pipelines.yml"),
    "JF":  (JenkinsContext, JenkinsfileChecks, "Jenkinsfile"),
}


def _run_one_check(check_id: str, snippet: str, tmp_path: Path) -> Finding:
    """Write *snippet* to disk, scan with the right provider, return the
    finding for *check_id* with ControlRefs enriched (mirrors what the
    real Scanner does post-run)."""
    prefix = check_id.split("-", 1)[0]
    ctx_cls, check_cls, fname = _PROVIDER_BY_PREFIX[prefix]
    p = tmp_path / fname
    p.write_text(snippet, encoding="utf-8")
    ctx = ctx_cls.from_path(p)
    findings = check_cls(ctx).run()
    target = next((f for f in findings if f.check_id == check_id), None)
    assert target is not None, (
        f"check {check_id} produced no finding from the snippet; "
        f"either the snippet is malformed or the check is mis-IDed."
    )
    # Enrich exactly the way Scanner does — full registry, all standards.
    active = standards_mod.resolve()
    target.controls = standards_mod.resolve_for_check(check_id, active)
    return target


def _assert_owasp(finding: Finding, expected: str) -> None:
    owasp = [
        c.control_id for c in finding.controls
        if c.standard == "owasp_cicd_top_10"
    ]
    assert expected in owasp, (
        f"{finding.check_id}: expected OWASP {expected} in controls, "
        f"got {owasp}"
    )


def _assert_esf(finding: Finding, expected: tuple[str, ...]) -> None:
    esf = [
        c.control_id for c in finding.controls
        if c.standard == "esf_supply_chain"
    ]
    for ctrl in expected:
        assert ctrl in esf, (
            f"{finding.check_id}: expected ESF {ctrl} in controls, got {esf}"
        )


# ──────────────────────────────────────────────────────────────────────
# Snippet catalogue — one entry per check.
# ──────────────────────────────────────────────────────────────────────


# Some shared scaffolding that lets a "safe" GHA snippet pass even
# though the targeted check isn't the only one in the file.
_GHA_SAFE_HEADER = """\
name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
"""


CASES: list[CheckCase] = [
    # ── GitHub Actions ───────────────────────────────────────────────
    CheckCase(
        check_id="GHA-001",
        unsafe="""\
name: build
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        safe="""\
name: build
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
    CheckCase(
        check_id="GHA-002",
        unsafe="""\
name: pr-target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
        safe="""\
name: pr
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION", "ESF-D-BUILD-ENV"),
    ),
    CheckCase(
        check_id="GHA-003",
        unsafe="""\
name: comment-bot
on: issue_comment
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Got comment ${{ github.event.comment.body }}"
""",
        safe="""\
name: comment-bot
on: issue_comment
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{ github.event.comment.body }}
        run: echo "Got comment $BODY"
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION",),
    ),
    CheckCase(
        check_id="GHA-004",
        unsafe="""\
name: build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
""",
        safe="""\
name: build
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
""",
        expected_owasp="CICD-SEC-5",
        expected_esf=("ESF-C-LEAST-PRIV",),
    ),
    CheckCase(
        check_id="GHA-005",
        unsafe="""\
name: deploy
on: push
permissions: { contents: read }
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
""",
        safe="""\
name: deploy
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-deployer
          aws-region: us-east-1
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-TOKEN-HYGIENE",),
    ),
    CheckCase(
        check_id="GHA-006",
        unsafe="""\
name: release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: docker build -t app:$GITHUB_SHA .
""",
        safe="""\
name: release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@4959ce089c2fe0a3ab7b3aaa3aebc6a0a17b2af9
      - run: cosign sign --yes ghcr.io/example/app:$GITHUB_SHA
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SIGN-ARTIFACTS",),
    ),
    CheckCase(
        check_id="GHA-007",
        unsafe="""\
name: release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cosign sign --yes example/app:$GITHUB_SHA
""",
        safe="""\
name: release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: syft . -o cyclonedx-json > sbom.json
      - run: cosign sign --yes example/app:$GITHUB_SHA
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SBOM",),
    ),
    CheckCase(
        check_id="GHA-008",
        unsafe="""\
name: deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - env:
          DEBUG_AWS_KEY: AKIAIOSFODNN7EXAMPLE
        run: ./deploy.sh
""",
        safe="""\
name: deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - env:
          DEBUG_AWS_KEY: ${{ secrets.AWS_ACCESS_KEY_ID }}
        run: ./deploy.sh
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),

    # ── GitLab CI ────────────────────────────────────────────────────
    CheckCase(
        check_id="GL-001",
        unsafe="""\
image: python:latest
build:
  script: [pytest]
""",
        safe="""\
image: python:3.12.1-slim
build:
  script: [pytest]
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
    CheckCase(
        check_id="GL-002",
        unsafe="""\
build:
  script:
    - echo "Building MR ${CI_MERGE_REQUEST_TITLE}"
""",
        safe="""\
build:
  script:
    - TITLE="$CI_MERGE_REQUEST_TITLE"
    - echo "Building MR $TITLE"
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION",),
    ),
    CheckCase(
        check_id="GL-003",
        unsafe="""\
variables:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
build:
  script: [echo build]
""",
        safe="""\
variables:
  DEPLOY_ENV: production
build:
  script: [echo build]
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="GL-004",
        unsafe="""\
deploy-prod:
  stage: deploy
  script: [./deploy.sh]
""",
        safe="""\
deploy-prod:
  stage: deploy
  when: manual
  environment:
    name: production
    url: https://app.example.com
  script: [./deploy.sh]
""",
        expected_owasp="CICD-SEC-1",
        expected_esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    ),
    CheckCase(
        check_id="GL-005",
        unsafe="""\
include:
  - project: 'templates/ci'
    ref: main
""",
        safe="""\
include:
  - project: 'templates/ci'
    ref: v1.4.2
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    ),
    CheckCase(
        check_id="GL-006",
        unsafe="""\
release:
  script:
    - docker build -t app:$CI_COMMIT_SHA .
""",
        safe="""\
release:
  script:
    - cosign sign --yes "$CI_REGISTRY_IMAGE@$DIGEST"
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SIGN-ARTIFACTS",),
    ),
    CheckCase(
        check_id="GL-007",
        unsafe="""\
release:
  script:
    - cosign sign --yes example/app:$CI_COMMIT_SHA
""",
        safe="""\
release:
  script:
    - syft . -o cyclonedx-json > sbom.json
    - cosign sign --yes example/app:$CI_COMMIT_SHA
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SBOM",),
    ),
    CheckCase(
        check_id="GL-008",
        unsafe="""\
build:
  script:
    - echo "deploying with AKIAIOSFODNN7EXAMPLE"
""",
        safe="""\
build:
  script:
    - echo "deploying with $AWS_ACCESS_KEY_ID"
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="GL-009",
        unsafe="""\
image: python:3.12.1-slim
build:
  script: [pytest]
""",
        safe="""\
image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
build:
  script: [pytest]
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    ),

    # ── Bitbucket Pipelines ──────────────────────────────────────────
    CheckCase(
        check_id="BB-001",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - pipe: atlassian/aws-s3-deploy:1
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - pipe: atlassian/aws-s3-deploy:1.4.0
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
    CheckCase(
        check_id="BB-002",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - echo "Building $BITBUCKET_BRANCH"
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - BRANCH="$BITBUCKET_BRANCH"
          - echo "Building $BRANCH"
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION",),
    ),
    CheckCase(
        check_id="BB-003",
        unsafe="""\
definitions:
  variables:
    AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
pipelines:
  default:
    - step: { max-time: 10, script: [pytest] }
""",
        safe="""\
definitions:
  variables:
    DEPLOY_ENV: production
pipelines:
  default:
    - step: { max-time: 10, script: [pytest] }
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="BB-004",
        unsafe="""\
pipelines:
  default:
    - step:
        name: Deploy to production
        max-time: 10
        script: [./deploy.sh]
""",
        safe="""\
pipelines:
  default:
    - step:
        name: Deploy to production
        deployment: production
        max-time: 10
        script: [./deploy.sh]
""",
        expected_owasp="CICD-SEC-1",
        expected_esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    ),
    CheckCase(
        check_id="BB-005",
        unsafe="""\
pipelines:
  default:
    - step:
        name: Build
        script: [pytest]
""",
        safe="""\
pipelines:
  default:
    - step:
        name: Build
        max-time: 20
        script: [pytest]
""",
        expected_owasp="CICD-SEC-7",
        expected_esf=("ESF-D-BUILD-TIMEOUT",),
    ),
    CheckCase(
        check_id="BB-006",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - docker build -t app .
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - cosign sign --yes registry.example.com/app:$BITBUCKET_COMMIT
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SIGN-ARTIFACTS",),
    ),
    CheckCase(
        check_id="BB-007",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - cosign sign --yes example/app:$BITBUCKET_COMMIT
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - syft . -o cyclonedx-json > sbom.json
          - cosign sign --yes example/app:$BITBUCKET_COMMIT
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SBOM",),
    ),
    CheckCase(
        check_id="BB-008",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - echo "Deploying with AKIAIOSFODNN7EXAMPLE"
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - echo "Deploying with $AWS_ACCESS_KEY_ID"
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="BB-009",
        unsafe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - pipe: atlassian/aws-s3-deploy:1.4.0
""",
        safe="""\
pipelines:
  default:
    - step:
        max-time: 10
        script:
          - pipe: atlassian/aws-s3-deploy@sha256:0000000000000000000000000000000000000000000000000000000000000001
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    ),

    # ── Azure DevOps Pipelines ───────────────────────────────────────
    CheckCase(
        check_id="ADO-001",
        unsafe="""\
jobs:
  - job: Build
    steps:
      - task: DotNetCoreCLI@2
        inputs:
          command: 'build'
""",
        safe="""\
jobs:
  - job: Build
    steps:
      - task: DotNetCoreCLI@2.210.0
        inputs:
          command: 'build'
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
    CheckCase(
        check_id="ADO-002",
        unsafe="""\
jobs:
  - job: Build
    steps:
      - script: echo "Building $(Build.SourceBranchName)"
""",
        safe="""\
jobs:
  - job: Build
    steps:
      - script: BRANCH="$(Build.SourceBranchName)"
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION",),
    ),
    CheckCase(
        check_id="ADO-003",
        unsafe="""\
variables:
  - name: AWS_ACCESS_KEY_ID
    value: AKIAIOSFODNN7EXAMPLE
jobs:
  - job: Build
    steps:
      - script: pytest
""",
        safe="""\
variables:
  - name: BUILD_CONFIG
    value: Release
jobs:
  - job: Build
    steps:
      - script: pytest
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="ADO-004",
        unsafe="""\
jobs:
  - deployment: DeployWeb
    strategy:
      runOnce:
        deploy:
          steps:
            - task: AzureWebApp@1.200.0
""",
        safe="""\
jobs:
  - deployment: DeployWeb
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
            - task: AzureWebApp@1.200.0
""",
        expected_owasp="CICD-SEC-1",
        expected_esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    ),
    CheckCase(
        check_id="ADO-005",
        unsafe="""\
resources:
  containers:
    - container: py
      image: python:latest
jobs:
  - job: Build
    container: py
    steps: [{script: pytest}]
""",
        safe="""\
resources:
  containers:
    - container: py
      image: python:3.12.1-slim
jobs:
  - job: Build
    container: py
    steps: [{script: pytest}]
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    ),
    CheckCase(
        check_id="ADO-006",
        unsafe="""\
jobs:
  - job: Release
    steps:
      - script: docker build -t app .
""",
        safe="""\
jobs:
  - job: Release
    steps:
      - script: cosign sign --yes registry.example.com/app:$(Build.BuildId)
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SIGN-ARTIFACTS",),
    ),
    CheckCase(
        check_id="ADO-007",
        unsafe="""\
jobs:
  - job: Release
    steps:
      - script: cosign sign --yes example/app:$(Build.BuildId)
""",
        safe="""\
jobs:
  - job: Release
    steps:
      - script: syft . -o cyclonedx-json > sbom.json
      - script: cosign sign --yes example/app:$(Build.BuildId)
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SBOM",),
    ),
    CheckCase(
        check_id="ADO-008",
        unsafe="""\
jobs:
  - job: Build
    steps:
      - script: echo "Deploying with AKIAIOSFODNN7EXAMPLE"
""",
        safe="""\
jobs:
  - job: Build
    steps:
      - script: echo "Deploying with $(AWS_ACCESS_KEY_ID)"
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="ADO-009",
        unsafe="""\
resources:
  containers:
    - container: py
      image: python:3.12.1-slim
jobs:
  - job: Build
    container: py
    steps: [{script: pytest}]
""",
        safe="""\
resources:
  containers:
    - container: py
      image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
jobs:
  - job: Build
    container: py
    steps: [{script: pytest}]
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    ),

    # ── Jenkins ──────────────────────────────────────────────────────
    CheckCase(
        check_id="JF-001",
        unsafe="""\
@Library('shared-pipeline@main') _
pipeline { agent { label 'build' } }
""",
        safe="""\
@Library('shared-pipeline@v1.4.2') _
pipeline { agent { label 'build' } }
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
    CheckCase(
        check_id="JF-002",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Build') {
      steps { sh "echo Building ${env.BRANCH_NAME}" }
    }
  }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Build') {
      steps {
        withEnv(["BRANCH=${env.BRANCH_NAME}"]) {
          sh 'echo "Building $BRANCH"'
        }
      }
    }
  }
}
""",
        expected_owasp="CICD-SEC-4",
        expected_esf=("ESF-D-INJECTION",),
    ),
    CheckCase(
        check_id="JF-003",
        unsafe="""\
pipeline { agent any; stages { stage('B') { steps { sh 'pytest' } } } }
""",
        safe="""\
pipeline { agent { label 'build-pool' }; stages { stage('B') { steps { sh 'pytest' } } } }
""",
        expected_owasp="CICD-SEC-5",
        expected_esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    ),
    CheckCase(
        check_id="JF-004",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Deploy') {
      steps {
        withCredentials([string(credentialsId: 'aws-prod-key', variable: 'AWS_ACCESS_KEY_ID')]) {
          sh './deploy.sh'
        }
      }
    }
  }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Deploy') {
      steps {
        withAWS(role: 'arn:aws:iam::111122223333:role/jenkins-prod') {
          sh './deploy.sh'
        }
      }
    }
  }
}
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-TOKEN-HYGIENE",),
    ),
    CheckCase(
        check_id="JF-005",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Deploy to production') {
      steps { sh './deploy.sh' }
    }
  }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Deploy to production') {
      input { message 'Promote to prod?'; submitter 'releasers' }
      steps { sh './deploy.sh' }
    }
  }
}
""",
        expected_owasp="CICD-SEC-1",
        expected_esf=("ESF-C-APPROVAL",),
    ),
    CheckCase(
        check_id="JF-006",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages { stage('Release') { steps { sh 'docker build -t app .' } } }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  stages { stage('Release') { steps { sh 'cosign sign --yes app:$BUILD_TAG' } } }
}
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SIGN-ARTIFACTS",),
    ),
    CheckCase(
        check_id="JF-007",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages { stage('Release') { steps { sh 'cosign sign --yes app:$BUILD_TAG' } } }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Release') {
      steps {
        sh 'syft . -o cyclonedx-json > sbom.json'
        sh 'cosign sign --yes app:$BUILD_TAG'
      }
    }
  }
}
""",
        expected_owasp="CICD-SEC-9",
        expected_esf=("ESF-D-SBOM",),
    ),
    CheckCase(
        check_id="JF-008",
        unsafe="""\
pipeline {
  agent { label 'build' }
  environment { DEBUG = 'AKIAIOSFODNN7EXAMPLE' }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  environment { DEBUG = credentials('aws-prod-key') }
}
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS",),
    ),
    CheckCase(
        check_id="JF-009",
        unsafe="""\
pipeline { agent { docker { image 'maven:latest' } } }
""",
        safe="""\
pipeline { agent { docker { image 'maven@sha256:0000000000000000000000000000000000000000000000000000000000000001' } } }
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"),
    ),
    CheckCase(
        check_id="JF-010",
        unsafe="""\
pipeline {
  agent { label 'build' }
  environment { AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE" }
}
""",
        safe="""\
pipeline {
  agent { label 'build' }
  environment { AWS_ACCESS_KEY_ID = credentials('aws-prod-key') }
}
""",
        expected_owasp="CICD-SEC-6",
        expected_esf=("ESF-D-SECRETS", "ESF-D-TOKEN-HYGIENE"),
    ),
    CheckCase(
        check_id="JF-011",
        unsafe="""\
pipeline { agent { label 'build' } }
""",
        safe="""\
pipeline {
  agent { label 'build' }
  options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }
}
""",
        expected_owasp="CICD-SEC-10",
        expected_esf=("ESF-D-BUILD-LOGS", "ESF-C-AUDIT"),
    ),
    CheckCase(
        check_id="JF-012",
        unsafe="""\
pipeline {
  agent { label 'build' }
  stages {
    stage('Bootstrap') {
      steps { script { def helpers = load 'ci/helpers.groovy' } }
    }
  }
}
""",
        safe="""\
@Library('helpers@v1.0.0') _
pipeline {
  agent { label 'build' }
  stages { stage('Bootstrap') { steps { sh 'echo ready' } } }
}
""",
        expected_owasp="CICD-SEC-3",
        expected_esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    ),
]


# ──────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.check_id)
def test_unsafe_snippet_triggers_check_with_correct_standards(case, tmp_path):
    """The unsafe snippet must produce a FAILING finding for the targeted
    check, and that finding must carry the expected OWASP (and ESF
    where mapped) ControlRefs."""
    f = _run_one_check(case.check_id, case.unsafe, tmp_path)
    assert f.passed is False, (
        f"{case.check_id}: unsafe snippet did NOT trigger the check.\n"
        f"--- snippet ---\n{case.unsafe}"
    )
    _assert_owasp(f, case.expected_owasp)
    if case.expected_esf:
        _assert_esf(f, case.expected_esf)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.check_id)
def test_safe_snippet_does_not_trigger_check(case, tmp_path):
    """The safe snippet must produce a PASSING finding for the targeted
    check. Other checks may pass or fail — we only assert behaviour for
    the targeted ID."""
    f = _run_one_check(case.check_id, case.safe, tmp_path)
    assert f.passed is True, (
        f"{case.check_id}: safe snippet triggered the check unexpectedly.\n"
        f"description: {f.description}\n"
        f"--- snippet ---\n{case.safe}"
    )


def test_every_workflow_check_has_a_case():
    """Lock in that this catalogue stays in sync with the registered
    workflow checks. If a new check ships without an entry here, this
    test fails — forcing the author to write a real-example case."""
    expected_ids = (
        {f"GHA-{i:03d}" for i in range(1, 9)}
        | {f"GL-{i:03d}" for i in range(1, 10)}
        | {f"BB-{i:03d}" for i in range(1, 10)}
        | {f"ADO-{i:03d}" for i in range(1, 10)}
        | {f"JF-{i:03d}" for i in range(1, 13)}
    )
    covered = {c.check_id for c in CASES}
    missing = expected_ids - covered
    assert not missing, (
        f"per-check catalogue is missing entries for: {sorted(missing)}. "
        f"Add a CheckCase for each so future regressions are caught."
    )
