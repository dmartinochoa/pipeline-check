# NSA/CISA ESF — Securing the Software Supply Chain

- **Version:** 2022
- **URL:** https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers
- **Scope:** Mitigations from the three-volume Enduring Security
  Framework guidance — Developer (2022), Supplier (2022), Customer
  (2022) — that this scanner can evidence from AWS, GitHub Actions,
  GitLab CI, Bitbucket Pipelines, Azure DevOps Pipelines, and Terraform
  state.

The Enduring Security Framework is a cross-agency working group led by
the NSA and CISA (with ODNI) that publishes practical guidance for
critical-infrastructure operators. Its software-supply-chain series
turns the post-SolarWinds / Log4Shell lessons into concrete pipeline
mitigations: harden the build environment, verify third-party inputs,
sign and attest every artifact, and gate deployment behind monitored
approvals. Control IDs follow `ESF-<volume>-<topic>` where the volume
is **D**eveloper, **S**upplier, or **C**ustomer.

## Controls evidenced

| Control                   | Description                                                              |
|---------------------------|--------------------------------------------------------------------------|
| ESF-D-BUILD-ENV           | Harden the build environment (isolated, minimal, ephemeral workers)      |
| ESF-D-BUILD-LOGS          | Generate and preserve build audit logs                                   |
| ESF-D-BUILD-TIMEOUT       | Enforce bounded build execution (single-use, time-limited)               |
| ESF-D-SECRETS             | Protect secrets used during build; no secrets in source or env           |
| ESF-D-PRIV-BUILD          | Avoid privileged / host-networked build workers                          |
| ESF-D-SIGN-ARTIFACTS      | Sign build artifacts and verify signatures before release                |
| ESF-D-SBOM                | Produce SBOM / provenance metadata with every build                      |
| ESF-D-CODE-REVIEW         | Require peer review of source and pipeline configuration                 |
| ESF-D-TOKEN-HYGIENE       | Use short-lived, federated credentials (OIDC) — not long-lived tokens    |
| ESF-D-INJECTION           | Prevent script / template injection from untrusted pipeline context      |
| ESF-S-VERIFY-DEPS         | Verify third-party and open-source dependencies before use               |
| ESF-S-PIN-DEPS            | Pin dependencies / actions / images to immutable digests                 |
| ESF-S-TRUSTED-REG         | Use only trusted, authenticated package and image registries             |
| ESF-S-VULN-MGMT           | Scan inbound artifacts (images, packages) for known vulnerabilities      |
| ESF-S-IMMUTABLE           | Enforce artifact / tag immutability to preserve provenance               |
| ESF-C-APPROVAL            | Require explicit approval before production deployment                   |
| ESF-C-ROLLBACK            | Automated rollback on deployment failure or alarm                        |
| ESF-C-DEPLOY-MON          | Monitor deployments with alarms / health checks                          |
| ESF-C-ENV-SEP             | Separate deployment environments (dev / staging / prod)                  |
| ESF-C-ARTIFACT-AUTHZ      | Restrict access to artifact storage and deployment pipelines             |
| ESF-C-LEAST-PRIV          | Apply least-privilege to CI/CD service roles and pipelines               |
| ESF-C-AUDIT               | Audit deployment / pipeline activity and retain logs                     |

## Selected check → control mappings

Highlights — the full mapping dict lives in
[`pipeline_check/core/standards/data/esf_supply_chain.py`](../../pipeline_check/core/standards/data/esf_supply_chain.py).

| Check      | ESF control(s)                                 |
|------------|------------------------------------------------|
| CB-002     | ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD              |
| CB-003     | ESF-D-BUILD-LOGS, ESF-C-AUDIT                  |
| CB-005     | ESF-S-VERIFY-DEPS, ESF-S-PIN-DEPS              |
| CP-002     | ESF-D-SIGN-ARTIFACTS, ESF-C-ARTIFACT-AUTHZ     |
| CD-001     | ESF-C-ROLLBACK                                 |
| ECR-001    | ESF-S-VULN-MGMT, ESF-S-VERIFY-DEPS             |
| ECR-002    | ESF-S-IMMUTABLE, ESF-D-SBOM                    |
| IAM-005    | ESF-C-LEAST-PRIV, ESF-D-TOKEN-HYGIENE          |
| S3-002     | ESF-D-SIGN-ARTIFACTS                           |
| GHA-001    | ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS              |
| GHA-005    | ESF-D-TOKEN-HYGIENE                            |
| GHA-006    | ESF-D-SIGN-ARTIFACTS                           |
| GHA-007    | ESF-D-SBOM                                     |
| GL-006     | ESF-D-SIGN-ARTIFACTS                           |
| GL-007     | ESF-D-SBOM                                     |
| BB-006     | ESF-D-SIGN-ARTIFACTS                           |
| BB-007     | ESF-D-SBOM                                     |
| ADO-006    | ESF-D-SIGN-ARTIFACTS                           |
| ADO-007    | ESF-D-SBOM                                     |

## Not covered

- Developer-guide items that require SCM introspection (branch
  protection, mandatory review policy) beyond what the pipeline YAML
  declares.
- Supplier-guide registry provenance / signature-verification steps
  that happen outside the pipeline definition.
- Customer-guide operational controls (incident response, vendor risk
  management) that are process, not configuration.
