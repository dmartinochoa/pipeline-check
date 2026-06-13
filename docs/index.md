---
title: "Pipeline-Check: CI/CD Security Posture Scanner"
template: home.html
hide:
  - navigation
  - toc
---

<section class="pg-hero" markdown>
<div class="pg-hero__inner" markdown>

<div markdown>
<div class="pg-hero__mark" role="img" aria-label="Pipeline-Check: shield with checkmark">
  <svg viewBox="0 0 64 64" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
    <path d="M32 6 L54 13 V31 C54 44.5 44.5 53.5 32 58 C19.5 53.5 10 44.5 10 31 V13 Z" fill="none" stroke="#f0f2f5" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M22 32 L29 39 L43 24" stroke="#1ba3a9" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  </svg>
</div>

<span class="pg-hero__wordmark">pipeline-check · v{{ version }}</span>

# Catch supply-chain risks <span class="accent">before they ship.</span>

<p class="pg-hero__lede">
A read-only scanner for 39 providers, graded against 18 compliance frameworks. 
120 of the 1220+ checks also emit a one-shot patch you can apply with <code>--fix</code>.
</p>

<div class="pg-hero__cta">
  <a class="md-button" href="usage/">Get started</a>
  <a class="md-button" href="https://github.com/dmartinochoa/pipeline-check" target="_blank" rel="noopener">View on GitHub</a>
</div>

<div class="pg-hero__meta">
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> MIT licensed</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No telemetry</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No API tokens</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Python 3.11+</span>
</div>
</div>

<div class="pg-terminal">
  <p class="pg-visually-hidden">Example scan of a GitHub Actions repository. Running <code>pipeline_check --pipeline github</code> reports 16 findings (2 critical, 4 high, 7 medium, 3 low) for a score of 47 out of 100, grade D. Findings map to OWASP CI/CD Top 10, NIST SSDF, SLSA, and CIS Supply Chain. 4 of the 16 are auto-fixable with <code>--apply</code>.</p>
  <div class="pg-terminal__chrome" aria-hidden="true">
    <span class="pg-terminal__file">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      payments-api · github
    </span>
    <span class="pg-terminal__tag">scan</span>
  </div>
<div class="pg-terminal__body" aria-hidden="true"><span class="line l1"><span class="prompt">$</span> <span class="pg-terminal__cmd">pipeline_check <span class="arg">--pipeline github</span></span></span><span class="line l2"> </span><span class="line l3"><span class="label">Pipeline-Check</span> v{{ version }} · scanning <span class="dim">.github/workflows/</span> <span class="pg-terminal__spin"></span></span><span class="line l4"> </span><span class="line l5">  <span class="crit">CRITICAL</span>  GHA-008  Credential-shaped literal in workflow body</span><span class="line l6">            <span class="dim">.github/workflows/release.yml:31  echo "token=ghp_…"</span></span><span class="line l7">  <span class="high">HIGH    </span>  GHA-001  Action not pinned to commit SHA</span><span class="line l8">            <span class="dim">.github/workflows/release.yml:14  uses: actions/checkout@v4</span></span><span class="line l9">  <span class="high">HIGH    </span>  GHA-016  Remote script piped to shell interpreter</span><span class="line l10">            <span class="dim">.github/workflows/build.yml:42  curl … | bash</span></span><span class="line l11">  <span class="med">MEDIUM  </span>  GHA-015  Job has no timeout-minutes, unbounded build</span><span class="line l12">            <span class="dim">.github/workflows/test.yml:9  job: test</span></span><span class="line l13"> </span><span class="line l14"><span class="label">Score</span>  <span class="pg-terminal__score" data-score="47">47</span> / 100   <span class="grade-d pg-terminal__grade">Grade D</span></span><span class="line l15">        <span class="dim">2 critical · 4 high · 7 medium · 3 low</span></span><span class="line l16"> </span><span class="line l17"><span class="label">Standards</span>  OWASP CI/CD Top 10 · NIST SSDF · SLSA · CIS Supply Chain</span><span class="line l18"> </span><span class="line l19"><span class="ok">→</span> Fix suggestions written to <span class="dim">pipeline-check.sarif</span></span><span class="line l20"><span class="ok">→</span> Run with <span class="dim">--apply</span> to autofix 4 of 16 findings.<span class="pg-cursor"></span></span></div>
</div>

</div>
</section>

<section class="pg-stats" data-reveal>
<div class="pg-stats__inner">
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="1220">1220+</div><div class="pg-stat__label">Checks</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="39">39</div><div class="pg-stat__label">Providers</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="18">18</div><div class="pg-stat__label">Compliance standards</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="120">120</div><div class="pg-stat__label">Autofixers</div></div>
</div>
</section>

<section class="pg-section" data-reveal markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// capabilities</div>
<h2 class="pg-section__title">One scanner. Every pipeline you ship through.</h2>
<p class="pg-section__lede">
Same severity model and report format whether you're scanning a Jenkinsfile,
Terraform (plan JSON or raw HCL), or a live AWS account. Findings carry control IDs for OWASP,
NIST SSDF, SLSA, and the rest, so audit answers don't require leaving the tool.
</p>
</div>

<div class="pg-features" data-stagger markdown>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
</div>
### OWASP 10/10 coverage
Every one of the OWASP Top 10 CI/CD Security Risks has at least one rule across
the supported providers. New risks land here before they land in your pipeline.
<a class="pg-feature__link" href="standards/owasp_cicd_top_10/">Read OWASP coverage</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
</div>
### Live AWS + shift-left IaC
Scan a running AWS account through boto3, *or* scan Terraform plans (or raw HCL source) and
CloudFormation templates before provisioning. Same rule IDs, same severities.
<a class="pg-feature__link" href="providers/aws/">AWS reference</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
</div>
### Attack-chain correlation
56 multi-finding chains mapped to MITRE ATT&CK, including the cross-provider
`XPC-NNN` family that fires when GitHub Actions, Dockerfile, Helm, and OCI
findings line up in one scan. The `TAINT-NNN` dataflow engine follows
attacker-controllable input across cross-step boundaries on five providers
(GitHub Actions, GitLab CI, Buildkite, Tekton, Argo Workflows), each routed
through that host's native channel: `$GITHUB_OUTPUT`, dotenv artifact,
`buildkite-agent meta-data`, Tekton results, Argo `outputs.parameters`.
<a class="pg-feature__link" href="attack_chains/">Attack chains</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/><path d="M11 8v3l2 2"/></svg>
</div>
### Supply-chain depth on demand
`--resolve-remote` turns on the network-backed checks: a cooldown gate on freshly
published packages, OSV advisory lookups, OpenSSF Scorecard and build-provenance
signals, and live secret verification that probes a leaked credential against its
issuing API (two dozen services) and promotes a confirmed-live token to CRITICAL.
Off by default so the base scan stays hermetic.
<a class="pg-feature__link" href="usage/#what-resolve-remote-unlocks">Supply-chain checks</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7l9-4 9 4-9 4-9-4z"/><path d="M3 12l9 4 9-4"/><path d="M3 17l9 4 9-4"/></svg>
</div>
### Benchmarked on real goats
Recall is locked against deliberately-vulnerable training repos: 100% on
`cicd-goat`, `cfngoat`, and `kubernetes-goat`. Every rule change that stops a
goat finding from firing trips the bench in CI, so coverage can't silently
regress between releases.
<a class="pg-feature__link" href="goat_bench/">GOAT bench</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
</div>
### Findings that fix themselves
120 of the checks ship a one-shot patch. `--fix` prints a unified diff you can
pipe to `git apply`, `--apply` writes the edits in place, and the `fix-pr`
subcommand commits them to a fresh branch and opens the pull request (or GitLab
MR). Fixers carry a `safe` / `unsafe` tier, so the default pass only touches
edits that can't change behavior, and they're idempotent.
<a class="pg-feature__link" href="ci_gate/#autofix-fix">Autofix</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
</div>
### CI gate that does its job
Severity thresholds, baseline diffs against a git ref, ignore files with
expiries, glob check selection, autofix emit-or-apply. Failing the build is
the default; turning it off is opt-in.
<a class="pg-feature__link" href="ci_gate/">CI gate</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M7 7l4 9M17 7l-4 9"/></svg>
</div>
### Org-wide fleet scanning
Point `fleet --from-org <org>` (or `--repos repos.yml`) at a whole GitHub /
GitLab / Bitbucket org. It clones and scans every repo in parallel, writes one
graded digest ranked worst-first, and re-runs the cross-repo `CXPC-NNN` attack
chains over the union, catching risks that only exist *between* repos. A posture
graph (repos as nodes, cross-repo chains as edges) ships in `fleet.json`.
<a class="pg-feature__link" href="fleet/">Fleet scanning</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
</div>
### Output that integrates
Rich terminal table for humans, JSON / JSON Lines for scripts and log
pipelines, HTML report (with a per-resource blast-radius heatmap and an
attack-chains panel) for sharing, SARIF 2.1.0 for GitHub code scanning and
Defender for DevOps, CycloneDX + SPDX SBOMs, plus markdown for PR comments,
GitHub Actions annotations, CSV, and JUnit XML for test-runner UIs.
<a class="pg-feature__link" href="output/">Output formats</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
</div>
### Inline in your editor
The Pipeline-Check VS Code extension drives the same rule registry as the CLI,
surfaced as you edit workflow files. Install from the
<a href="https://marketplace.visualstudio.com/items?itemName=greylag-ci.pipeline-check">VS Code Marketplace</a>
or <a href="https://open-vsx.org/extension/greylag-ci/pipeline-check">Open VSX</a>;
source lives at <a href="https://github.com/greylag-ci/pipeline-check-vscode">greylag-ci/pipeline-check-vscode</a>.
<a class="pg-feature__link" href="vscode/">VS Code extension</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/><circle cx="9" cy="10" r="1"/><circle cx="15" cy="10" r="1"/></svg>
</div>
### MCP server for AI clients
Drive scans and introspect the rule catalog from Claude Desktop, Claude Code,
Cursor, Continue, or Zed over the Model Context Protocol. Runs locally on
stdio: no network egress, no telemetry, no API tokens.
<a class="pg-feature__link" href="mcp/">MCP server</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
</div>
### Zero phone-home
Workflow files are parsed from disk. AWS uses the standard boto3 credential
chain. Nothing leaves your machine. MIT licensed, no signup, no account.
<a class="pg-feature__link" href="https://github.com/dmartinochoa/pipeline-check">GitHub</a>
</div>

</div>
</section>

<section class="pg-section" data-reveal markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// providers</div>
<h2 class="pg-section__title">Wherever your builds run.</h2>
<p class="pg-section__lede">
Auto-detect picks the provider for you, or pass <code>--pipeline &lt;name&gt;</code>
to force one. Counts reflect the current rule catalog.
</p>
</div>

<div class="pg-provider-group" data-stagger>
  <span class="pg-provider-group__label">CI/CD platforms</span>
  <a class="pg-provider" href="providers/github/"><span class="pg-provider__name">GitHub Actions</span><span class="pg-provider__count">{{ providers.github.checks }}</span></a>
  <a class="pg-provider" href="providers/gitlab/"><span class="pg-provider__name">GitLab CI</span><span class="pg-provider__count">{{ providers.gitlab.checks }}</span></a>
  <a class="pg-provider" href="providers/bitbucket/"><span class="pg-provider__name">Bitbucket Pipelines</span><span class="pg-provider__count">{{ providers.bitbucket.checks }}</span></a>
  <a class="pg-provider" href="providers/azure/"><span class="pg-provider__name">Azure DevOps</span><span class="pg-provider__count">{{ providers.azure.checks }}</span></a>
  <a class="pg-provider" href="providers/jenkins/"><span class="pg-provider__name">Jenkins</span><span class="pg-provider__count">{{ providers.jenkins.checks }}</span></a>
  <a class="pg-provider" href="providers/circleci/"><span class="pg-provider__name">CircleCI</span><span class="pg-provider__count">{{ providers.circleci.checks }}</span></a>
  <a class="pg-provider" href="providers/cloudbuild/"><span class="pg-provider__name">Google Cloud Build</span><span class="pg-provider__count">{{ providers.cloudbuild.checks }}</span></a>
  <a class="pg-provider" href="providers/buildkite/"><span class="pg-provider__name">Buildkite</span><span class="pg-provider__count">{{ providers.buildkite.checks }}</span></a>
  <a class="pg-provider" href="providers/drone/"><span class="pg-provider__name">Drone CI</span><span class="pg-provider__count">{{ providers.drone.checks }}</span></a>
  <a class="pg-provider" href="providers/tekton/"><span class="pg-provider__name">Tekton</span><span class="pg-provider__count">{{ providers.tekton.checks }}</span></a>
  <a class="pg-provider" href="providers/argo/"><span class="pg-provider__name">Argo Workflows</span><span class="pg-provider__count">{{ providers.argo.checks }}</span></a>
  <a class="pg-provider" href="providers/gitea/"><span class="pg-provider__name">Gitea / Forgejo Actions</span><span class="pg-provider__count">{{ providers.gitea.checks }}</span></a>
</div>

<div class="pg-provider-group" data-stagger>
  <span class="pg-provider-group__label">Cloud & infrastructure as code</span>
  <a class="pg-provider" href="providers/aws/"><span class="pg-provider__name">AWS</span><span class="pg-provider__count">{{ providers.aws.checks }}</span></a>
  <a class="pg-provider" href="providers/azure_cloud/"><span class="pg-provider__name">Azure Cloud</span><span class="pg-provider__count">{{ providers.azure_cloud.checks }}</span></a>
  <a class="pg-provider" href="providers/gcp/"><span class="pg-provider__name">GCP</span><span class="pg-provider__count">{{ providers.gcp.checks }}</span></a>
  <a class="pg-provider" href="providers/terraform/"><span class="pg-provider__name">Terraform</span><span class="pg-provider__count">{{ providers.terraform.checks }}</span></a>
  <a class="pg-provider" href="providers/cloudformation/"><span class="pg-provider__name">CloudFormation</span><span class="pg-provider__count">{{ providers.cloudformation.checks }}</span></a>
  <a class="pg-provider" href="providers/pulumi/"><span class="pg-provider__name">Pulumi</span><span class="pg-provider__count">{{ providers.pulumi.checks }}</span></a>
</div>

<div class="pg-provider-group" data-stagger>
  <span class="pg-provider-group__label">Containers & deployment</span>
  <a class="pg-provider" href="providers/dockerfile/"><span class="pg-provider__name">Dockerfile</span><span class="pg-provider__count">{{ providers.dockerfile.checks }}</span></a>
  <a class="pg-provider" href="providers/modelfile/"><span class="pg-provider__name">Modelfile</span><span class="pg-provider__count">{{ providers.modelfile.checks }}</span></a>
  <a class="pg-provider" href="providers/kubernetes/"><span class="pg-provider__name">Kubernetes</span><span class="pg-provider__count">{{ providers.kubernetes.checks }}</span></a>
  <a class="pg-provider" href="providers/helm/"><span class="pg-provider__name">Helm</span><span class="pg-provider__count">{{ providers.helm.checks }}</span></a>
  <a class="pg-provider" href="providers/argocd/"><span class="pg-provider__name">Argo CD</span><span class="pg-provider__count">{{ providers.argocd.checks }}</span></a>
  <a class="pg-provider" href="providers/oci/"><span class="pg-provider__name">OCI manifest</span><span class="pg-provider__count">{{ providers.oci.checks }}</span></a>
</div>

<div class="pg-provider-group" data-stagger>
  <span class="pg-provider-group__label">SCM posture</span>
  <a class="pg-provider" href="providers/scm/"><span class="pg-provider__name">GitHub</span><span class="pg-provider__count">{{ providers.scm.checks }}</span></a>
  <a class="pg-provider" href="providers/scm/"><span class="pg-provider__name">GitLab</span><span class="pg-provider__count">{{ providers.scm.checks }}</span></a>
  <a class="pg-provider" href="providers/scm/"><span class="pg-provider__name">Bitbucket</span><span class="pg-provider__count">{{ providers.scm.checks }}</span></a>
</div>

<div class="pg-provider-group" data-stagger>
  <span class="pg-provider-group__label">Package registries</span>
  <a class="pg-provider" href="providers/npm/"><span class="pg-provider__name">npm</span><span class="pg-provider__count">{{ providers.npm.checks }}</span></a>
  <a class="pg-provider" href="providers/pypi/"><span class="pg-provider__name">PyPI</span><span class="pg-provider__count">{{ providers.pypi.checks }}</span></a>
  <a class="pg-provider" href="providers/maven/"><span class="pg-provider__name">Maven</span><span class="pg-provider__count">{{ providers.maven.checks }}</span></a>
  <a class="pg-provider" href="providers/nuget/"><span class="pg-provider__name">NuGet</span><span class="pg-provider__count">{{ providers.nuget.checks }}</span></a>
  <a class="pg-provider" href="providers/gomod/"><span class="pg-provider__name">Go modules</span><span class="pg-provider__count">{{ providers.gomod.checks }}</span></a>
  <a class="pg-provider" href="providers/cargo/"><span class="pg-provider__name">Cargo (Rust)</span><span class="pg-provider__count">{{ providers.cargo.checks }}</span></a>
  <a class="pg-provider" href="providers/composer/"><span class="pg-provider__name">Composer (PHP)</span><span class="pg-provider__count">{{ providers.composer.checks }}</span></a>
  <a class="pg-provider" href="providers/rubygems/"><span class="pg-provider__name">RubyGems (Ruby)</span><span class="pg-provider__count">{{ providers.rubygems.checks }}</span></a>
</div>
</section>

<section class="pg-section" data-reveal markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// flow</div>
<h2 class="pg-section__title">Inputs in. Graded report out.</h2>
<p class="pg-section__lede">Click any stage to jump to its reference page.</p>
</div>

<div class="pg-pipeline" data-stagger>
  <a class="pg-pipe pg-pipe--src" href="usage/">
    <span class="pg-pipe__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
    <span class="pg-pipe__label">Input</span>
    <span class="pg-pipe__desc">Repo on disk or live cloud account</span>
  </a>
  <a class="pg-pipe" href="providers/">
    <span class="pg-pipe__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg></span>
    <span class="pg-pipe__label">Adapter</span>
    <span class="pg-pipe__desc">Auto-detect or <code>--pipeline</code></span>
  </a>
  <a class="pg-pipe" href="attack_chains/">
    <span class="pg-pipe__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
    <span class="pg-pipe__label">Rule engine</span>
    <span class="pg-pipe__desc">1220+ checks with severity and fix</span>
  </a>
  <a class="pg-pipe" href="standards/">
    <span class="pg-pipe__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7l9-4 9 4-9 4-9-4z"/><path d="M3 12l9 4 9-4"/><path d="M3 17l9 4 9-4"/></svg></span>
    <span class="pg-pipe__label">Compliance map</span>
    <span class="pg-pipe__desc">18 frameworks (OWASP, NIST, SLSA, CIS)</span>
  </a>
  <a class="pg-pipe" href="scoring_model/">
    <span class="pg-pipe__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></span>
    <span class="pg-pipe__label">Scorer</span>
    <span class="pg-pipe__desc">0 &ndash; 100 score, graded A / B / C / D</span>
  </a>
</div>

<div class="pg-pipeline-out">
  <div class="pg-pipeline-out__formats">
  <div class="pg-pipeline-out__header">Output formats</div>
  <div class="pg-pipeline-out__row" data-stagger>
    <a class="pg-pipe-out" href="output/#terminal">
      <span class="pg-pipe-out__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></span>
      <span class="pg-pipe-out__name">Terminal</span>
      <span class="pg-pipe-out__desc">Rich color table for humans</span>
    </a>
    <a class="pg-pipe-out" href="output/#json">
      <span class="pg-pipe-out__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5a2 2 0 0 0 2 2h1"/><path d="M16 3h1a2 2 0 0 1 2 2v5a2 2 0 0 0 2 2 2 2 0 0 0-2 2v5a2 2 0 0 1-2 2h-1"/></svg></span>
      <span class="pg-pipe-out__name">JSON</span>
      <span class="pg-pipe-out__desc">Machine-parseable for scripts</span>
    </a>
    <a class="pg-pipe-out" href="output/#html">
      <span class="pg-pipe-out__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
      <span class="pg-pipe-out__name">HTML report</span>
      <span class="pg-pipe-out__desc">Client-side filters, shareable</span>
    </a>
    <a class="pg-pipe-out" href="output/#sarif">
      <span class="pg-pipe-out__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg></span>
      <span class="pg-pipe-out__name">SARIF 2.1.0</span>
      <span class="pg-pipe-out__desc">GitHub code scanning, Defender</span>
    </a>
  </div>
  </div>
  <div class="pg-pipeline-gate" data-stagger>
    <a class="pg-pipe-gate" href="ci_gate/">
      <span class="pg-pipe-gate__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></span>
      <span class="pg-pipe-gate__label">CI gate</span>
    </a>
    <span class="pg-pipe-result pg-pipe-result--pass">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      Merge
    </span>
    <span class="pg-pipe-result pg-pipe-result--fail">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      Block
    </span>
  </div>
</div>
</section>

<section class="pg-section" data-reveal markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// the patrol</div>
<h2 class="pg-section__title">Every commit walks the same rail.</h2>
</div>

<div class="pg-patrol">
  <img class="pg-patrol__embed" src="patrol.svg" alt="Pipeline-Check goose patrolling a CI/CD pipeline rail: pauses at the SCAN node, stamps DENIED, and turns back" loading="lazy">
</div>
</section>

<section class="pg-cta" data-reveal markdown>
<div class="pg-cta__inner" markdown>
## Ship pipelines you trust.
<p>Install in under 30 seconds. Scan your first repo in under a minute.</p>

<div class="pg-install">pip install pipeline-check</div>

<div class="pg-cta__buttons">
  <a class="md-button md-button--primary" href="usage/">Read the docs</a>
  <a class="md-button" href="https://github.com/dmartinochoa/pipeline-check">Star on GitHub</a>
</div>
</div>
</section>
