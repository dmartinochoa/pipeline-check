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
A read-only scanner for 27 providers, graded against 18 compliance frameworks. 
111 of the 970+ checks also emit a one-shot patch you can apply with <code>--fix</code>.
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

<div class="pg-terminal" aria-hidden="true">
  <div class="pg-terminal__chrome">
    <span class="pg-terminal__file">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      payments-api · github
    </span>
    <span class="pg-terminal__tag">scan</span>
  </div>
<div class="pg-terminal__body"><span class="line l1"><span class="prompt">$</span> pipeline_check <span class="arg">--pipeline github</span></span><span class="line l2"> </span><span class="line l3"><span class="label">Pipeline-Check</span> v{{ version }} · scanning <span class="dim">.github/workflows/</span></span><span class="line l4"> </span><span class="line l5">  <span class="crit">CRITICAL</span>  GHA-001  Action not pinned to commit SHA</span><span class="line l6">            <span class="dim">.github/workflows/release.yml:14  uses: actions/checkout@v4</span></span><span class="line l7">  <span class="high">HIGH    </span>  GHA-016  Pipe-to-shell from untrusted host</span><span class="line l8">            <span class="dim">.github/workflows/build.yml:42  curl … | bash</span></span><span class="line l9">  <span class="med">MEDIUM  </span>  GHA-023  TLS verification disabled</span><span class="line l10">            <span class="dim">.github/workflows/deploy.yml:88  curl --insecure</span></span><span class="line l11">  <span class="low">LOW     </span>  GHA-015  No timeout-minutes on job <span class="dim">test</span></span><span class="line l12"> </span><span class="line l13"><span class="label">Score</span>  47 / 100   <span class="grade-d">Grade D</span></span><span class="line l14">        <span class="dim">2 critical · 4 high · 7 medium · 3 low</span></span><span class="line l15"> </span><span class="line l16"><span class="label">Standards</span>  OWASP CI/CD Top 10 · NIST SSDF · SLSA · CIS Supply Chain</span><span class="line l17"> </span><span class="line l18"><span class="ok">→</span> Fix suggestions written to <span class="dim">pipeline-check.sarif</span></span><span class="line l19"><span class="ok">→</span> Run with <span class="dim">--apply</span> to autofix 4 of 16 findings.<span class="pg-cursor"></span></span></div>
</div>

</div>
</section>

<section class="pg-stats" data-reveal>
<div class="pg-stats__inner">
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="970">970+</div><div class="pg-stat__label">Checks</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="27">27</div><div class="pg-stat__label">Providers</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="18">18</div><div class="pg-stat__label">Compliance standards</div></div>
  <div class="pg-stat"><div class="pg-stat__num" data-count-to="111">111</div><div class="pg-stat__label">Autofixers</div></div>
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
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
</div>
### Attack-chain correlation
48 multi-finding chains mapped to MITRE ATT&CK, including the cross-provider
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
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
</div>
### Output that integrates
Rich terminal table for humans, JSON for scripts, HTML report (with a
per-resource blast-radius heatmap and an attack-chains panel) for sharing,
SARIF 2.1.0 for GitHub code scanning and Defender for DevOps, plus
markdown for PR comments and JUnit XML for test-runner UIs.
<a class="pg-feature__link" href="output/">Output formats</a>
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
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/><circle cx="9" cy="10" r="1"/><circle cx="15" cy="10" r="1"/></svg>
</div>
### MCP server for AI clients
Drive scans and introspect the rule catalog from Claude Desktop, Claude Code,
Cursor, Continue, or Zed over the Model Context Protocol. Runs locally on
stdio: no network egress, no telemetry, no API tokens.
<a class="pg-feature__link" href="mcp/">MCP server</a>
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

<div class="pg-providers" data-stagger>
  <a class="pg-provider" href="providers/aws/"><span class="pg-provider__name">AWS</span><span class="pg-provider__count">{{ providers.aws.checks }}</span></a>
  <a class="pg-provider" href="providers/terraform/"><span class="pg-provider__name">Terraform</span><span class="pg-provider__count">{{ providers.terraform.checks }}</span></a>
  <a class="pg-provider" href="providers/cloudformation/"><span class="pg-provider__name">CloudFormation</span><span class="pg-provider__count">{{ providers.cloudformation.checks }}</span></a>
  <a class="pg-provider" href="providers/github/"><span class="pg-provider__name">GitHub Actions</span><span class="pg-provider__count">{{ providers.github.checks }}</span></a>
  <a class="pg-provider" href="providers/gitlab/"><span class="pg-provider__name">GitLab CI</span><span class="pg-provider__count">{{ providers.gitlab.checks }}</span></a>
  <a class="pg-provider" href="providers/bitbucket/"><span class="pg-provider__name">Bitbucket</span><span class="pg-provider__count">{{ providers.bitbucket.checks }}</span></a>
  <a class="pg-provider" href="providers/azure/"><span class="pg-provider__name">Azure DevOps</span><span class="pg-provider__count">{{ providers.azure.checks }}</span></a>
  <a class="pg-provider" href="providers/jenkins/"><span class="pg-provider__name">Jenkins</span><span class="pg-provider__count">{{ providers.jenkins.checks }}</span></a>
  <a class="pg-provider" href="providers/circleci/"><span class="pg-provider__name">CircleCI</span><span class="pg-provider__count">{{ providers.circleci.checks }}</span></a>
  <a class="pg-provider" href="providers/cloudbuild/"><span class="pg-provider__name">Cloud Build</span><span class="pg-provider__count">{{ providers.cloudbuild.checks }}</span></a>
  <a class="pg-provider" href="providers/buildkite/"><span class="pg-provider__name">Buildkite</span><span class="pg-provider__count">{{ providers.buildkite.checks }}</span></a>
  <a class="pg-provider" href="providers/drone/"><span class="pg-provider__name">Drone CI</span><span class="pg-provider__count">{{ providers.drone.checks }}</span></a>
  <a class="pg-provider" href="providers/tekton/"><span class="pg-provider__name">Tekton</span><span class="pg-provider__count">{{ providers.tekton.checks }}</span></a>
  <a class="pg-provider" href="providers/argo/"><span class="pg-provider__name">Argo Workflows</span><span class="pg-provider__count">{{ providers.argo.checks }}</span></a>
  <a class="pg-provider" href="providers/argocd/"><span class="pg-provider__name">Argo CD</span><span class="pg-provider__count">{{ providers.argocd.checks }}</span></a>
  <a class="pg-provider" href="providers/dockerfile/"><span class="pg-provider__name">Dockerfile</span><span class="pg-provider__count">{{ providers.dockerfile.checks }}</span></a>
  <a class="pg-provider" href="providers/kubernetes/"><span class="pg-provider__name">Kubernetes</span><span class="pg-provider__count">{{ providers.kubernetes.checks }}</span></a>
  <a class="pg-provider" href="providers/helm/"><span class="pg-provider__name">Helm</span><span class="pg-provider__count">{{ providers.helm.checks }}</span></a>
  <a class="pg-provider" href="providers/oci/"><span class="pg-provider__name">OCI manifest</span><span class="pg-provider__count">{{ providers.oci.checks }}</span></a>
  <a class="pg-provider pg-provider--wide" href="providers/scm/"><span class="pg-provider__name">SCM posture (GitHub / GitLab / Bitbucket)</span><span class="pg-provider__count">{{ providers.scm.checks }}</span></a>
  <a class="pg-provider pg-provider--wide" href="providers/registries/"><span class="pg-provider__name">Package registries (npm / PyPI / Maven / NuGet)</span><span class="pg-provider__count">{{ providers.registries.checks }}</span></a>
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
    <span class="pg-pipe__desc">970+ checks with severity and fix</span>
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
  <div class="pg-pipeline-out__row" data-stagger>
    <a class="pg-pipe-out" href="output/#terminal">
      <span class="pg-pipe-out__name">Terminal</span>
      <span class="pg-pipe-out__desc">Rich color table for humans</span>
    </a>
    <a class="pg-pipe-out" href="output/#json">
      <span class="pg-pipe-out__name">JSON</span>
      <span class="pg-pipe-out__desc">Machine-parseable for scripts</span>
    </a>
    <a class="pg-pipe-out" href="output/#html">
      <span class="pg-pipe-out__name">HTML report</span>
      <span class="pg-pipe-out__desc">Client-side filters, shareable</span>
    </a>
    <a class="pg-pipe-out" href="output/#sarif">
      <span class="pg-pipe-out__name">SARIF 2.1.0</span>
      <span class="pg-pipe-out__desc">GitHub code scanning, Defender</span>
    </a>
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
  <img class="pg-patrol__embed" src="patrol.svg" alt="Pipeline-Check goose patrolling a CI/CD pipeline rail: pauses at the SCAN node and stamps a build DENIED" loading="lazy">
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
