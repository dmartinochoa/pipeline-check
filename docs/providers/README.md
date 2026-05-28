# Providers

A **provider** binds a CI/CD platform to the scanner: it builds the API
context (credentials, clients) and declares which check modules run against
it. The scanner's core is provider-agnostic. Adding a new platform never
requires editing `Scanner`, `Reporter`, or the CLI.

### CI/CD platforms

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="github/">
    <h3>GitHub Actions</h3>
    <p>Scans every workflow under <code>.github/workflows/</code>. Action pinning, OIDC trust, secret hygiene, runner posture.</p>
    <span class="pg-doc-card__meta">{{ providers.github.checks }}</span>
  </a>
  <a class="pg-doc-card" href="gitlab/">
    <h3>GitLab CI</h3>
    <p>Parses <code>.gitlab-ci.yml</code> with <code>include:</code> resolution. Image pinning, deploy gating, manual-job posture.</p>
    <span class="pg-doc-card__meta">{{ providers.gitlab.checks }}</span>
  </a>
  <a class="pg-doc-card" href="bitbucket/">
    <h3>Bitbucket Pipelines</h3>
    <p>Parses <code>bitbucket-pipelines.yml</code>. Pipe pinning, deployment posture, custom-pipe risk.</p>
    <span class="pg-doc-card__meta">{{ providers.bitbucket.checks }}</span>
  </a>
  <a class="pg-doc-card" href="azure/">
    <h3>Azure DevOps</h3>
    <p>Parses <code>azure-pipelines.yml</code> with template-resolution support.</p>
    <span class="pg-doc-card__meta">{{ providers.azure.checks }}</span>
  </a>
  <a class="pg-doc-card" href="jenkins/">
    <h3>Jenkins</h3>
    <p>Lexes Declarative + Scripted <code>Jenkinsfile</code>s. Credential exposure, agent pinning, sandbox bypass.</p>
    <span class="pg-doc-card__meta">{{ providers.jenkins.checks }}</span>
  </a>
  <a class="pg-doc-card" href="circleci/">
    <h3>CircleCI</h3>
    <p>Parses <code>.circleci/config.yml</code> with orb-mapping support.</p>
    <span class="pg-doc-card__meta">{{ providers.circleci.checks }}</span>
  </a>
  <a class="pg-doc-card" href="cloudbuild/">
    <h3>Google Cloud Build</h3>
    <p>Parses <code>cloudbuild.yaml</code>. Substitution injection, secret retrieval, signing posture.</p>
    <span class="pg-doc-card__meta">{{ providers.cloudbuild.checks }}</span>
  </a>
  <a class="pg-doc-card" href="buildkite/">
    <h3>Buildkite</h3>
    <p>Parses <code>.buildkite/pipeline.yml</code>. Plugin pinning, agent-tag injection, command-step posture, TLS bypass.</p>
    <span class="pg-doc-card__meta">{{ providers.buildkite.checks }}</span>
  </a>
  <a class="pg-doc-card" href="drone/">
    <h3>Drone CI</h3>
    <p>Parses <code>.drone.yml</code> / <code>.drone.yaml</code>. Image and plugin pinning, privileged steps, template-variable injection, literal secrets, TLS bypass.</p>
    <span class="pg-doc-card__meta">{{ providers.drone.checks }}</span>
  </a>
  <a class="pg-doc-card" href="tekton/">
    <h3>Tekton</h3>
    <p>Parses <code>Task</code>, <code>Pipeline</code>, and <code>*Run</code> CRDs. Step image pinning, parameter injection, workspace hygiene.</p>
    <span class="pg-doc-card__meta">{{ providers.tekton.checks }}</span>
  </a>
  <a class="pg-doc-card" href="argo/">
    <h3>Argo Workflows</h3>
    <p>Parses <code>Workflow</code> and <code>WorkflowTemplate</code> CRDs. Image pinning, parameter injection, container template posture.</p>
    <span class="pg-doc-card__meta">{{ providers.argo.checks }}</span>
  </a>
  <a class="pg-doc-card" href="gitea/">
    <h3>Gitea / Forgejo</h3>
    <p>Scans <code>.gitea/workflows/</code> and <code>.forgejo/workflows/</code>. Reuses the full GitHub Actions rule pack (GHA-* IDs).</p>
    <span class="pg-doc-card__meta">{{ providers.github.checks }}</span>
  </a>
</div>

### Cloud & infrastructure as code

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="aws/">
    <h3>AWS</h3>
    <p>Live account scan via boto3. CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, S3, CloudTrail, Lambda, KMS, and more.</p>
    <span class="pg-doc-card__meta">{{ providers.aws.checks }}</span>
  </a>
  <a class="pg-doc-card" href="azure_cloud/">
    <h3>Azure Cloud</h3>
    <p>Live subscription scan via the <code>azure-mgmt-*</code> management SDKs. Entra ID, Storage, Key Vault, Container Registry, Monitor.</p>
    <span class="pg-doc-card__meta">{{ providers.azure_cloud.checks }}</span>
  </a>
  <a class="pg-doc-card" href="gcp/">
    <h3>GCP</h3>
    <p>Live project scan via the <code>google-cloud-*</code> client libraries. IAM, Cloud Storage, Cloud KMS, Artifact Registry, Cloud Logging.</p>
    <span class="pg-doc-card__meta">{{ providers.gcp.checks }}</span>
  </a>
  <a class="pg-doc-card" href="terraform/">
    <h3>Terraform</h3>
    <p>Shift-left scan against a <code>terraform show -json</code> plan or raw <code>*.tf</code> source. AWS-rule parity so findings match the live runtime.</p>
    <span class="pg-doc-card__meta">{{ providers.terraform.checks }}</span>
  </a>
  <a class="pg-doc-card" href="cloudformation/">
    <h3>CloudFormation</h3>
    <p>Parses YAML or JSON templates with intrinsic-function resolution (<code>!Ref</code>, <code>!Sub</code>, <code>!GetAtt</code>).</p>
    <span class="pg-doc-card__meta">{{ providers.cloudformation.checks }}</span>
  </a>
  <a class="pg-doc-card" href="pulumi/">
    <h3>Pulumi</h3>
    <p>Parses <code>Pulumi.yaml</code> + <code>Pulumi.&lt;stack&gt;.yaml</code> plus source files (Python / TypeScript / Go / C#). Secrets-provider posture, plaintext credentials, wildcard IAM policies, insecure state backend, unguarded StackReference.</p>
    <span class="pg-doc-card__meta">{{ providers.pulumi.checks }}</span>
  </a>
</div>

### Containers & deployment

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="dockerfile/">
    <h3>Dockerfile</h3>
    <p>Parses <code>Dockerfile</code> / <code>Containerfile</code>. Image pinning, USER hygiene, secret-in-env, RUN posture.</p>
    <span class="pg-doc-card__meta">{{ providers.dockerfile.checks }}</span>
  </a>
  <a class="pg-doc-card" href="kubernetes/">
    <h3>Kubernetes</h3>
    <p>Parses manifest YAML (Deployment, Pod, Job, …). securityContext, hostPath, RBAC blast radius, Secret hygiene.</p>
    <span class="pg-doc-card__meta">{{ providers.kubernetes.checks }}</span>
  </a>
  <a class="pg-doc-card" href="helm/">
    <h3>Helm</h3>
    <p>Renders charts via <code>helm template</code> and runs the full K8S-* rule pack on the result, plus a chart-supply-chain pack (<code>HELM-001..010</code>: legacy schema, unlocked dependencies, plaintext repos) that reads <code>Chart.yaml</code> straight off disk.</p>
    <span class="pg-doc-card__meta">{{ providers.helm.checks }}</span>
  </a>
  <a class="pg-doc-card" href="argocd/">
    <h3>Argo CD</h3>
    <p>Parses <code>Application</code>, <code>ApplicationSet</code>, and <code>AppProject</code> CRDs plus <code>argocd-cm</code> / <code>argocd-rbac-cm</code> ConfigMaps. Source repos, destinations, RBAC, auto-sync, PR generators.</p>
    <span class="pg-doc-card__meta">{{ providers.argocd.checks }}</span>
  </a>
  <a class="pg-doc-card" href="oci/">
    <h3>OCI image manifest</h3>
    <p>Parses <code>docker buildx imagetools inspect --raw</code> JSON. Provenance annotations, build attestations (SLSA / SBOM), <code>image.created</code> timestamp.</p>
    <span class="pg-doc-card__meta">{{ providers.oci.checks }}</span>
  </a>
</div>

### SCM posture

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="scm_github/">
    <h3>GitHub</h3>
    <p>Full 49-rule pack via REST API. Branch protection, rulesets, security features, environments, deploy keys, webhooks, outside collaborators, Actions permissions.</p>
    <span class="pg-doc-card__meta">{{ providers.scm.checks }}</span>
  </a>
  <a class="pg-doc-card" href="scm_gitlab/">
    <h3>GitLab</h3>
    <p>Seven universal rules via REST API: branch protection, required reviews, signed commits, force-push, status checks, branch deletion, CODEOWNERS.</p>
    <span class="pg-doc-card__meta">7 checks (universal subset)</span>
  </a>
  <a class="pg-doc-card" href="scm_bitbucket/">
    <h3>Bitbucket Cloud</h3>
    <p>Seven universal rules via REST API: branch restrictions, required approvals, force-push, passing builds, branch deletion, CODEOWNERS.</p>
    <span class="pg-doc-card__meta">7 checks (universal subset)</span>
  </a>
</div>

### Package registries

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="registries/">
    <h3>npm / PyPI / Maven / NuGet</h3>
    <p>Static parse of <code>package.json</code>, <code>requirements*.txt</code>, <code>pom.xml</code>, and <code>*.csproj</code>. Floating versions, missing integrity hashes, plaintext-HTTP indexes, lifecycle scripts, dependency-confusion source mapping, and curated known-compromised version registries. Live OSV advisory lookup behind <code>--resolve-remote</code>.</p>
    <span class="pg-doc-card__meta">{{ providers.registries.checks }}</span>
  </a>
  <a class="pg-doc-card" href="gomod/">
    <h3>Go modules</h3>
    <p>Parses <code>go.mod</code> and probes for <code>go.sum</code>. Replace-directive misuse (local-path, cross-module), <code>+incompatible</code> requires, integrity-manifest presence, missing toolchain directive, and a curated known-compromised module registry.</p>
    <span class="pg-doc-card__meta">{{ providers.gomod.checks }}</span>
  </a>
  <a class="pg-doc-card" href="cargo/">
    <h3>Cargo (Rust)</h3>
    <p>Parses <code>Cargo.toml</code> via the TOML stdlib parser. Floating version specs, git deps without <code>rev</code>, missing <code>Cargo.lock</code>, path dependencies, alternate-registry sources, and a curated known-compromised crate registry.</p>
    <span class="pg-doc-card__meta">{{ providers.cargo.checks }}</span>
  </a>
</div>

## Adding a new provider

1. Create `pipeline_check/core/providers/<name>.py` subclassing `BaseProvider`.
2. Set `NAME`, implement `build_context(**kwargs)` and `check_classes`.
3. Register it in `pipeline_check/core/providers/__init__.py`.
4. Add check modules under `pipeline_check/core/checks/<name>/` and tests
   under `tests/<name>/`.
5. (Optional) Add compliance mappings for the new check IDs in
   `pipeline_check/core/standards/data/*.py`.

The `Scanner`, `--pipeline` CLI flag, and provider registry pick it up
automatically.
