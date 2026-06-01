# How Pipeline-Check compares

Pipeline-Check overlaps with several well-known scanners. This page is
the short version of "is this the right tool for me?" so you don't
have to grep through five readmes.

The matrix below reflects feature coverage as we understand it. Treat
it as a starting point. Tools move fast, your mileage will vary, and
we'd rather you correct a row than trust it blindly. PRs welcome.

## At a glance

| Tool | Best at | Pipeline-Check overlaps with |
|------|---------|------------------------------|
| **Pipeline-Check** | CI/CD pipeline configs across many providers, with cross-step taint and attack-chain correlation | n/a |
| **Checkov** | Terraform / CloudFormation / Kubernetes / Helm IaC misconfig | IaC providers |
| **KICS** | IaC + a growing CI/CD query pack | IaC + GHA / GitLab |
| **Semgrep** | Source-code SAST with custom rule writing | rule-DSL, taint (different scope) |
| **tfsec** | Terraform-only, fast pre-commit (now merged into Trivy; still maintained as a standalone binary) | Terraform |
| **Trivy** | Container images, SBOM, vulnerabilities | OCI / Dockerfile / Kubernetes |
| **gitleaks** | Secret scanning across git history | Inline credential scanning only |
| **Snyk IaC** | Hosted IaC scanning with policy management | IaC providers (commercial) |

## Feature matrix

Legend: Yes = first-class, native rule pack. Partial = some coverage,
missing major surfaces or requires extra config. No = not in scope.

| Capability | Pipeline-Check | Checkov | KICS | Semgrep | tfsec | Trivy |
|---|---|---|---|---|---|---|
| **CI/CD pipeline configs** | | | | | | |
| GitHub Actions | Yes (102 rules) | Partial | Yes | Partial | No | No |
| GitLab CI | Yes (39) | No | Partial | No | No | No |
| Jenkins (Declarative + Scripted) | Yes (35) | No | No | Partial | No | No |
| CircleCI | Yes (33) | No | Partial | No | No | No |
| Azure DevOps | Yes (31) | No | Partial | No | No | No |
| Bitbucket Pipelines | Yes (32) | No | No | No | No | No |
| Google Cloud Build | Yes (26) | No | Partial | No | No | No |
| Buildkite | Yes (16) | No | No | No | No | No |
| Drone CI | Yes (16) | No | No | No | No | No |
| Tekton | Yes (16) | No | Partial | No | No | No |
| Argo Workflows | Yes (16) | No | Partial | No | No | No |
| Argo CD | Yes (13) | No | No | No | No | No |
| **SCM posture (governance)** | | | | | | |
| GitHub repo branch protection / secret scanning / Dependabot | Yes (55, `SCM-001..055`) | No | No | No | No | No |
| **Infrastructure as code** | | | | | | |
| Terraform plans | Yes | Yes | Yes | Partial | Yes | Yes |
| CloudFormation (YAML+JSON) | Yes | Yes | Yes | Partial | No | Yes |
| Kubernetes manifests | Yes (43) | Yes | Yes | No | No | Yes |
| Helm charts (rendered + supply-chain) | Yes (43 + 17) | Partial | No | No | No | Partial |
| Dockerfile | Yes (30) | Yes | Yes | No | No | Yes |
| **Cloud + supply-chain** | | | | | | |
| Live AWS account scan | Yes (71 rules, boto3) | No | No | No | No | Partial |
| Live Azure subscription scan | Yes (50 rules, azure-mgmt-*) | No | No | No | No | Partial |
| Live GCP project scan | Yes (50 rules, google-cloud-*) | No | No | No | No | Partial |
| OCI image manifests (provenance, SLSA) | Yes (16, incl. ATTEST-001..007 attestation content) | No | No | No | No | Partial |
| **Dependency supply chain** | | | | | | |
| Package registries (npm / PyPI / Maven / NuGet / Go / Cargo / Composer / RubyGems) | Yes (125 rules across 8 providers) | No | No | No | No | Partial |
| **Analysis depth** | | | | | | |
| Dataflow taint, multi-step / cross-job | Yes (TAINT-001..008 across 5 providers) | No | No | Rules-only | No | No |
| Cross-provider attack chains (MITRE ATT&CK) | Yes (51 chains: 37 AC + 10 XPC + 4 CXPC cross-repo) | No | No | No | No | No |
| Multi-scanner SARIF ingest + correlation | Yes (`--ingest`, `INGEST-<tool>-<rule>`, chain engine re-evaluates over the union) | No | No | No | No | No |
| Vulnerable-by-design benchmark | Yes (`bench/`, 6 cases, current recall 6/6, CI-gated) | No | No | No | No | No |
| Autofix patches (unified diff) | Yes (111 fixers) | Partial | No | Partial | No | No |
| Compliance frameworks (per-finding controls) | 18 (OWASP, SLSA, NIST SSDF, NIST 800-53, NIST 800-190, NIST CSF 2, CIS AWS, CIS Azure, CIS GCP, CIS GitHub, CIS Kubernetes, CIS Supply Chain, PCI DSS, SOC 2, ESF, OpenSSF, S2C2F, OSC&R) | Partial | Partial | Partial | No | Partial |
| Custom rule DSL | Yes (YAML) | No | Yes (Rego/JSON) | Yes (YAML) | No | Partial |
| Baseline / new-findings-only | Yes | Partial | No | Yes | No | No |
| Diff-mode (only changed files) | Yes | Partial | No | Partial | No | Partial |
| **Output and integration** | | | | | | |
| SARIF 2.1.0 | Yes | Yes | Yes | Yes | Yes | Yes |
| GitHub Actions marketplace action | Yes | Yes | Yes | Yes | Yes | Yes |
| Pre-commit hooks | Yes (per-provider) | Yes | Partial | Yes | Yes | Yes |
| Python API | Yes | Yes | No | Partial | No | No |
| **Project basics** | | | | | | |
| License | MIT | Apache 2.0 | Apache 2.0 | LGPL 2.1 | MIT | Apache 2.0 |
| Implementation language | Python | Python | Go | OCaml + Python | Go | Go |

## When Pipeline-Check is the right pick

- **You ship through more than one CI provider.** Pipeline-Check has
  one rule pack per provider, one CLI, one SARIF stream. Most of the
  alternatives cover one or two CI systems well and the rest as
  an afterthought.
- **Your threat model includes pipeline-as-attack-surface.** Checks
  like script injection (`${{ github.event.* }}` into `run:`),
  reusable-workflow taint, GitLab `extends:` chain taint, Argo
  cross-template `outputs.parameters`, and Tekton `results` flow are
  the core of the catalog, not bolt-ons.
- **You need cross-step or cross-job dataflow.** The TAINT-NNN family
  follows untrusted input across job/step/template boundaries that
  rule-only scanners miss.
- **You want findings tied to compliance controls.** Every finding
  carries a list of `ControlRef`s for the standards you've enabled, so
  one scan satisfies SOC 2, PCI DSS, NIST SSDF, and SLSA evidence at
  once.
- **You want autofix as code review, not just text.** `--fix` emits
  unified-diff patches; `--fix --apply` writes in place. 111 fixers
  cover script injection, secret literals, pinning, securityContext,
  Cloud Build options, Helm chart-supply-chain TODOs, and more.

## When something else is the right pick

- **Pure Terraform shop.** tfsec is purpose-built for that, runs in a
  blink, and integrates everywhere. Pipeline-Check covers Terraform
  too, but if Terraform is your only target the smaller tool is fine.
- **Container image vulnerability scanning.** Trivy is the standard.
  Pipeline-Check looks at the OCI manifest (provenance, attestations,
  digest hygiene); it does not scan layer contents for CVEs.
- **Source-code SAST.** Semgrep has the deepest taint engine for
  application source. Pipeline-Check's taint is scoped to CI/CD
  configurations, not your service code.
- **Secret scanning across git history.** gitleaks / trufflehog walk
  every commit. Pipeline-Check only flags secrets present in the
  current snapshot of pipeline configs.
- **You already have a hosted IaC platform.** Snyk IaC, Wiz, Prisma
  Cloud, and friends bundle policy management, ticketing, and
  reporting that an OSS CLI doesn't ship.

## Stacking, not replacing

Most teams that adopt Pipeline-Check keep one or two of the others:
Trivy for image CVEs, gitleaks for history, Semgrep for service code.
Pipeline-Check is the layer those tools don't cover, namely the
pipeline configs themselves and how they chain together.

## Corrections welcome

If a row is wrong or out of date, open an issue or a PR against this
file. The matrix is meant to be useful, not a marketing page.
