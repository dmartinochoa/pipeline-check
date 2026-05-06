# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-05-06

0.3.1 was tagged but the version-vs-tag guard caught that the bump
commit hadn't been merged. Re-cut as 0.3.2 with the bump on master.

### Added

- **Kubernetes manifest provider.** Parses K8s API documents
  (`Deployment`, `Pod`, `Job`, `CronJob`, `DaemonSet`, `StatefulSet`,
  `ReplicaSet`, `Service`, `Secret`, `Role`, `ClusterRole`,
  `RoleBinding`, `ClusterRoleBinding`) from YAML on disk. Multi-doc
  files and directories of manifests both work. Helm `values.yaml`,
  `Chart.yaml`, and kustomization files are silently skipped. New
  CLI flag `--k8s-path`, auto-detection of `kubernetes/`, `k8s/`,
  or `manifests/` at cwd. 22 checks (`K8S-001`..`K8S-022`) covering:
  image digest pinning, host-namespace sharing
  (`hostNetwork`/`hostPID`/`hostIPC`), `securityContext`
  (`privileged`, `allowPrivilegeEscalation`, `runAsNonRoot`,
  `readOnlyRootFilesystem`, capabilities, seccompProfile),
  service-account hygiene, `automountServiceAccountToken`,
  `hostPath` volumes (with a sensitive-path upgrade to CRITICAL for
  `docker.sock`, `/var/lib/kubelet`, `/etc`, `/`), resource limits,
  env-var and Secret credential leakage (with base64-decoded scans
  of `Secret.data`), default-namespace placement,
  ClusterRoleBinding to `cluster-admin` or `system:masters`,
  wildcard verbs+resources in Roles/ClusterRoles, and Services
  exposing port 22 (SSH).
- **Standards coverage for Kubernetes.** Every `K8S-*` rule is
  mapped into OWASP Top 10 CI/CD and NIST SP 800-190 (Application
  Container Security).
- **MANIFEST.in.** Defense-in-depth filter on the PyPI sdist to keep
  the GitHub Pages docs site, repo tooling, and local cache
  artifacts out of releases. Ships `CHANGELOG.md` (was previously
  absent from the sdist).
- **`tests/test_doc_claims.py`.** Locks the README and
  `docs/index.md` numerical claims (providers, standards,
  autofixers, attack chains, total checks) against the live
  registries so doc drift fails CI.
- **`tests/test_english_variant.py`.** Fails the suite if a British
  spelling lands in any tracked source or doc file. Convention
  documented in `CLAUDE.md`.

### Changed

- `pyproject.toml` description now lists every supported provider.
  CloudFormation, CircleCI, Cloud Build, and Dockerfile were
  previously omitted.
- README provider table, architecture ASCII, rule-tree listing, and
  the docs site landing page reconciled against the current rule
  catalog: 430+ checks across 12 providers. Older claims of "330+
  across 10/11" replaced.
- README logo points at the absolute GitHub raw URL so the PyPI
  long_description renders the image. The relative `docs/logo.png`
  path no longer resolved on PyPI after the sdist filter pruned
  `docs/`.
- Project switched to American English throughout. Convention
  documented in `CLAUDE.md`; bulk converter lives at
  `scripts/_apply_american_english.py`; enforcement via
  `tests/test_english_variant.py`.

### Fixed

- Config file loader (`core/config._TOPLEVEL_KEYS`) now accepts
  `cloudbuild_path`, `dockerfile_path`, `cfn_template`,
  `jenkinsfile_path`, and `k8s_path`. These keys were already
  documented by `pipeline_check init`'s scaffolded template but were
  silently rejected by the strict schema validator.

## [0.3.0] - 2026-05-05

### Added

- **Documentation site** — full MkDocs Material build deployed to
  GitHub Pages on every push to `master`. Hand-tuned landing page
  with an interactive scan-pipeline component, animated terminal,
  and brand-tinted typography across the provider, standards, and
  reference docs.
- **AWS IAM permissions reference** in `docs/providers/aws.md` —
  per-service permission map plus a copy-paste least-privilege
  IAM policy for running a full live-AWS scan, including a sample
  GitHub Actions OIDC trust policy.

### Changed

- Pinned `pymdown-extensions` to `10.21.2` to fix a fenced-code
  rendering bug present in 10.12 that mangled the language tag.
- GitHub Actions in `.github/workflows/docs.yml` are now pinned to
  commit SHAs (resolved from current major-version tags).
- `LocalStack Integration Test` workflow is now manual-trigger only
  (`workflow_dispatch`); push and nightly schedule triggers removed.

### Internal

- Dependabot kept dependencies and action SHAs current across the
  release window.

## [0.2.1] - 2026-04-20

### Added

- **Attack chains engine** — new `pipeline_check.core.chains` module with
  eight rules (`AC-001`..`AC-008`) that correlate individual findings into
  higher-signal attack paths (fork-PR credential theft, injection to
  unprotected deploy, unpinned action to credentials, self-hosted runner
  foothold, unsigned artifact to prod, cache poisoning, IAM privesc via
  CodeBuild, dependency confusion window).
- **Google Cloud Build expansion** — six additional checks (`GCB-010`..
  `GCB-015`) covering remote-script execution, TLS bypass, literal secrets,
  package source integrity, logging-disabled, and SBOM generation.
- **SARIF reporter** (`--output sarif`) — emits SARIF 2.1.0 for GitHub
  Code Scanning and other SARIF-aware tools.
- **`pipeline_check init`** — scaffolds a starter `.pipeline-check.yml`
  config with sensible defaults.
- **CodeQL workflow** and CI badges in the README.

### Changed

- `core/checks/base.py` refactored into smaller modules (`blob.py`,
  `tokens.py`, `_primitives/`) to reduce duplication across providers.
- `release.yml` now verifies the tag matches the built wheel version
  before uploading artifacts, failing early on version drift.

## [0.2.0] - 2026-04-17

First public release. Expands provider and standard coverage, adds two new
reporters, and hardens the HTML output for use in PR review workflows.

### Added

- **Google Cloud Build provider** — parses `cloudbuild.yaml`; ships 9 checks
  (`GCB-001`..`GCB-009`) covering step image pinning, secret handling, and
  substitution-variable injection.
- **Jenkins provider** — parses Declarative and Scripted `Jenkinsfile`s;
  ships 31 checks (`JF-001`..`JF-031`).
- **Terraform shift-left** — runs AWS-parity checks against
  `terraform show -json` plans before provisioning.
- **CloudFormation shift-left** — ~63 AWS-parity checks against YAML/JSON
  templates with `!Ref` / `!Sub` / `!GetAtt` intrinsic handling.
- **JUnit XML reporter** (`--output junit`) — groups findings into one
  `<testsuite>` per rule prefix so Jenkins / GitLab / Azure / CircleCI /
  GitHub Actions render them as native test rows.
- **Markdown reporter** (`--output markdown`) — GFM-compatible output for
  `$GITHUB_STEP_SUMMARY` and PR / MR comment bots. Failures table + passing
  checks collapsed in `<details>`.
- **Compliance standards** expanded from 3 to 13, including SLSA Build
  Track 1.0, NIST SSDF v1.1, NIST SP 800-53 Rev. 5, CIS Software Supply
  Chain 1.0, CIS AWS Foundations 3.0.0, PCI DSS v4.0, and NSA/CISA ESF
  Supply Chain.
- **`--standard-report`** CLI flag emits the control-to-check matrix for a
  standard, including gaps (controls with no mapped checks).
- **`--inventory`** / `--inventory-type` / `--inventory-only` — emit a
  scanned-component inventory alongside (or instead of) findings for
  asset-register and drift-detection use cases.
- **HTML reporter interactivity** — sticky filter bar, filter state
  round-tripped via URL query params, deep-link anchors with flash
  highlight, expand/collapse-all buttons, print stylesheet, keyboard
  shortcuts (`/` focuses filter, `Escape` clears it), and OS-aware theme
  toggle persisted to `localStorage`.
- **Provider HTML filter map** now covers every rule family
  (`GCB`, `CFN`, `SIGN`, `LMB`, `CA`, `CCM`, `CWL`, `KMS`, `SSM`, `EB`, …)
  so new checks don't silently collapse into an "other" bucket.
- **LocalStack integration test** pinned to 3.8 with a Terraform fixture,
  exercised in CI.
- **Dogfooding workflow** runs `pipeline_check` against its own
  `.github/workflows/` on every push.

### Changed

- **Rule counts** grew across every CI provider — GHA 27→29, GL 25→30,
  BB 25→27, ADO 26→28, JF 29→31, CC 26→30; AWS total 70→72.
- **SARIF reporter** now splits standard slugs into rule-level
  `properties.tags` (for GitHub code-scanning filters) and individual
  control IDs into per-result `properties.controls` (structured). This
  keeps rule tags under GitHub's 20-tag cap and lets kebab-case IDs
  (`Dangerous-Workflow`) round-trip cleanly.
- **CLI help text** uses ASCII fallbacks (`->`, `>=`) instead of `→` / `≥`
  so Windows `cmd.exe` (cp1252) can render `--help` without
  `UnicodeEncodeError`.

### Fixed

- **CLI stdio on Windows** — stdout / stderr are reconfigured with
  `errors="replace"` at import time so un-encodable characters degrade to
  `?` instead of crashing the process on legacy consoles.
- **HTML reporter** provider-prefix map no longer drops `GCB`, `CFN`,
  `SIGN`, `LMB`, `CA`, `CCM`, `CWL`, `KMS`, `SSM`, `EB`, `CW` — previously
  these collapsed to "other" and were unreachable from the Provider
  filter.

[0.2.0]: https://github.com/dmartinochoa/pipeline-check/releases/tag/v0.2.0
