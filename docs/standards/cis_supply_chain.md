# CIS Software Supply Chain Security Guide v1.0

- **Version:** 1.0
- **URL:** https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide
- **Scope:** Sub-controls from sections 1 (Source Code), 2 (Build
  Pipelines), 3 (Build Dependencies), 4 (Artifacts), and 5
  (Deployment) that this scanner can evidence from AWS, GitHub Actions,
  and Terraform state.

## Sections

- **1 Source Code** — contribution identity, 3rd-party verification
- **2 Build Pipelines** — build env hardening, worker isolation,
  pipeline integrity, audit logs
- **3 Build Dependencies** — signed metadata, trusted package managers
- **4 Artifacts** — signing, access controls, registry auth, SBOM
- **5 Deployment** — manifest review, env separation, audit

## Not covered

- 1.1 / 1.2 repository protection rules (requires SCM policy read)
- 2.1.1 / 2.1.2 build infra versioning (requires infra git history)
- 3.2.x dependency-graph SBOM verification (requires lockfile analysis)
- 5.1.1 / 5.1.2 deployment workflow review (requires SCM review-policy)
