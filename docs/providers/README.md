# Providers

A **provider** binds a CI/CD platform to the scanner: it builds the API
context (credentials, clients) and declares which check modules run against
it. The scanner's core is provider-agnostic. Adding a new platform never
requires editing `Scanner`, `Reporter`, or the CLI.

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="aws/">
    <h3>AWS</h3>
    <p>Live account scan via boto3. CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, S3, CloudTrail, Lambda, KMS, and more.</p>
  </a>
  <a class="pg-doc-card" href="terraform/">
    <h3>Terraform</h3>
    <p>Shift-left scan against a parsed <code>terraform show -json</code> plan. AWS-rule parity so findings match the live runtime.</p>
  </a>
  <a class="pg-doc-card" href="cloudformation/">
    <h3>CloudFormation</h3>
    <p>Parses YAML or JSON templates with intrinsic-function resolution (<code>!Ref</code>, <code>!Sub</code>, <code>!GetAtt</code>).</p>
  </a>
  <a class="pg-doc-card" href="github/">
    <h3>GitHub Actions</h3>
    <p>Scans every workflow under <code>.github/workflows/</code>. Action pinning, OIDC trust, secret hygiene, runner posture.</p>
  </a>
  <a class="pg-doc-card" href="gitlab/">
    <h3>GitLab CI</h3>
    <p>Parses <code>.gitlab-ci.yml</code> with <code>include:</code> resolution. Image pinning, deploy gating, manual-job posture.</p>
  </a>
  <a class="pg-doc-card" href="bitbucket/">
    <h3>Bitbucket Pipelines</h3>
    <p>Parses <code>bitbucket-pipelines.yml</code>. Pipe pinning, deployment posture, custom-pipe risk.</p>
  </a>
  <a class="pg-doc-card" href="azure/">
    <h3>Azure DevOps</h3>
    <p>Parses <code>azure-pipelines.yml</code> with template-resolution support.</p>
  </a>
  <a class="pg-doc-card" href="jenkins/">
    <h3>Jenkins</h3>
    <p>Lexes Declarative + Scripted <code>Jenkinsfile</code>s. Credential exposure, agent pinning, sandbox bypass.</p>
  </a>
  <a class="pg-doc-card" href="circleci/">
    <h3>CircleCI</h3>
    <p>Parses <code>.circleci/config.yml</code> with orb-mapping support.</p>
  </a>
  <a class="pg-doc-card" href="cloudbuild/">
    <h3>Google Cloud Build</h3>
    <p>Parses <code>cloudbuild.yaml</code>. Substitution injection, secret retrieval, signing posture.</p>
  </a>
  <a class="pg-doc-card" href="buildkite/">
    <h3>Buildkite</h3>
    <p>Parses <code>.buildkite/pipeline.yml</code>. Plugin pinning, agent-tag injection, command-step posture, TLS bypass.</p>
  </a>
  <a class="pg-doc-card" href="drone/">
    <h3>Drone CI</h3>
    <p>Parses <code>.drone.yml</code> / <code>.drone.yaml</code>. Image / plugin pinning, privileged steps, Drone-template-variable injection, literal secrets, TLS bypass.</p>
  </a>
  <a class="pg-doc-card" href="tekton/">
    <h3>Tekton</h3>
    <p>Parses <code>Task</code>, <code>Pipeline</code>, and <code>*Run</code> CRDs. Step image pinning, parameter injection, workspace hygiene.</p>
  </a>
  <a class="pg-doc-card" href="argo/">
    <h3>Argo Workflows</h3>
    <p>Parses <code>Workflow</code> and <code>WorkflowTemplate</code> CRDs. Image pinning, parameter injection, container template posture.</p>
  </a>
  <a class="pg-doc-card" href="dockerfile/">
    <h3>Dockerfile</h3>
    <p>Parses <code>Dockerfile</code> / <code>Containerfile</code>. Image pinning, USER hygiene, secret-in-env, RUN posture.</p>
  </a>
  <a class="pg-doc-card" href="kubernetes/">
    <h3>Kubernetes</h3>
    <p>Parses manifest YAML (Deployment, Pod, Job, …). securityContext, hostPath, RBAC blast radius, Secret hygiene.</p>
  </a>
  <a class="pg-doc-card" href="helm/">
    <h3>Helm</h3>
    <p>Renders charts via <code>helm template</code> and runs the full K8S-* rule pack on the result, plus a chart-supply-chain pack (<code>HELM-001..010</code>: legacy schema, unlocked dependencies, plaintext repos) that reads <code>Chart.yaml</code> straight off disk.</p>
  </a>
  <a class="pg-doc-card" href="oci/">
    <h3>OCI image manifest</h3>
    <p>Parses <code>docker buildx imagetools inspect --raw</code> JSON. Provenance annotations, build attestations (SLSA / SBOM), <code>image.created</code> timestamp.</p>
  </a>
  <a class="pg-doc-card" href="scm/">
    <h3>SCM (GitHub) posture</h3>
    <p>Hits the GitHub REST API for branch protection, required reviews, code scanning, secret scanning, Dependabot, signed commits. Closes the gap with Legitify and OpenSSF Scorecard.</p>
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
