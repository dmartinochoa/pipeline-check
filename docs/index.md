---
title: Pipeline-Check — CI/CD Security Posture Scanner
template: home.html
hide:
  - navigation
  - toc
---

<section class="pg-hero">
<div class="pg-hero__inner" markdown>

<div markdown>
<span class="pg-hero__wordmark">pipeline-check · v0.2.1</span>

# Catch supply-chain risks <span class="accent">before they ship.</span>

<p class="pg-hero__lede">
A read-only scanner for ten CI/CD providers and live AWS — graded against
the OWASP Top 10 CI/CD Risks plus twelve compliance frameworks. Every
finding ships with a control mapping, a fix, and a CI gate.
</p>

<div class="pg-hero__cta">
  <a class="md-button md-button--primary" href="usage/">Get started</a>
  <a class="md-button" href="https://github.com/dmartinochoa/pipeline-check" target="_blank" rel="noopener">View on GitHub</a>
</div>

<div class="pg-hero__meta">
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> MIT licensed</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No telemetry</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> No API tokens</span>
  <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Python 3.10+</span>
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
<div class="pg-terminal__body"><span class="line l1"><span class="prompt">$</span> pipeline_check <span class="arg">--pipeline github</span></span><span class="line l2"> </span><span class="line l3"><span class="label">Pipeline-Check</span> v0.2.1 · scanning <span class="dim">.github/workflows/</span></span><span class="line l4"> </span><span class="line l5">  <span class="crit">CRITICAL</span>  GHA-001  Action pinned to mutable tag</span><span class="line l6">            <span class="dim">.github/workflows/release.yml:14  uses: actions/checkout@v4</span></span><span class="line l7">  <span class="high">HIGH    </span>  GHA-016  Pipe-to-shell from untrusted host</span><span class="line l8">            <span class="dim">.github/workflows/build.yml:42  curl … | bash</span></span><span class="line l9">  <span class="med">MEDIUM  </span>  GHA-023  TLS verification disabled</span><span class="line l10">            <span class="dim">.github/workflows/deploy.yml:88  curl --insecure</span></span><span class="line l11">  <span class="low">LOW     </span>  GHA-015  No timeout-minutes on job <span class="dim">test</span></span><span class="line l12"> </span><span class="line l13"><span class="label">Score</span>  47 / 100   <span class="grade-d">Grade D</span></span><span class="line l14">        <span class="dim">2 critical · 4 high · 7 medium · 3 low</span></span><span class="line l15"> </span><span class="line l16"><span class="label">Standards</span>  OWASP CI/CD Top 10 · NIST SSDF · SLSA · CIS Supply Chain</span><span class="line l17"> </span><span class="line l18"><span class="ok">→</span> Fix suggestions written to <span class="dim">pipeline-check.sarif</span></span><span class="line l19"><span class="ok">→</span> Run with <span class="dim">--apply</span> to autofix 4 of 16 findings.<span class="pg-cursor"></span></span></div>
</div>

</div>
</section>

<section class="pg-stats">
<div class="pg-stats__inner">
  <div class="pg-stat"><div class="pg-stat__num">330+</div><div class="pg-stat__label">Checks</div></div>
  <div class="pg-stat"><div class="pg-stat__num">10</div><div class="pg-stat__label">Providers</div></div>
  <div class="pg-stat"><div class="pg-stat__num">13</div><div class="pg-stat__label">Compliance standards</div></div>
  <div class="pg-stat"><div class="pg-stat__num">68</div><div class="pg-stat__label">Autofixers</div></div>
</div>
</section>

<section class="pg-section" markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// capabilities</div>
<h2 class="pg-section__title">One scanner. Every pipeline you ship through.</h2>
<p class="pg-section__lede">
Same severity model and report format whether you're scanning a Jenkinsfile,
a Terraform plan, or a live AWS account. Findings carry control IDs for OWASP,
NIST SSDF, SLSA, and the rest — so audit answers don't require leaving the tool.
</p>
</div>

<div class="pg-features" markdown>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
</div>
### OWASP 10/10 coverage
Every one of the OWASP Top 10 CI/CD Security Risks has at least one rule across
the supported providers. New risks land here before they land in your pipeline.
<a class="pg-feature__link" href="standards/owasp_cicd_top_10/">Read more</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
</div>
### Live AWS + shift-left IaC
Scan a running AWS account through boto3, *or* scan Terraform plans and
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
Multi-finding chains mapped to MITRE ATT&CK. See the kill chain — token leak →
artifact poisoning → production push — instead of three disconnected findings.
<a class="pg-feature__link" href="attack_chains/">Attack chains</a>
</div>

<div class="pg-feature" markdown>
<div class="pg-feature__icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
</div>
### Output that integrates
Rich terminal table for humans, JSON for scripts, HTML report with client-side
filters for sharing, SARIF 2.1.0 for GitHub code scanning and Defender for DevOps.
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

</div>
</section>

<section class="pg-section" markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// providers</div>
<h2 class="pg-section__title">Wherever your builds run.</h2>
<p class="pg-section__lede">
Auto-detect picks the provider for you, or pass <code>--pipeline &lt;name&gt;</code>
to force one. Counts reflect the current rule catalogue.
</p>
</div>

<div class="pg-providers">
  <a class="pg-provider" href="providers/aws/"><span class="pg-provider__name">AWS</span><span class="pg-provider__count">71 checks</span></a>
  <a class="pg-provider" href="providers/terraform/"><span class="pg-provider__name">Terraform</span><span class="pg-provider__count">aws-parity</span></a>
  <a class="pg-provider" href="providers/cloudformation/"><span class="pg-provider__name">CloudFormation</span><span class="pg-provider__count">~63 checks</span></a>
  <a class="pg-provider" href="providers/github/"><span class="pg-provider__name">GitHub Actions</span><span class="pg-provider__count">29 checks</span></a>
  <a class="pg-provider" href="providers/gitlab/"><span class="pg-provider__name">GitLab CI</span><span class="pg-provider__count">30 checks</span></a>
  <a class="pg-provider" href="providers/bitbucket/"><span class="pg-provider__name">Bitbucket</span><span class="pg-provider__count">27 checks</span></a>
  <a class="pg-provider" href="providers/azure/"><span class="pg-provider__name">Azure DevOps</span><span class="pg-provider__count">28 checks</span></a>
  <a class="pg-provider" href="providers/jenkins/"><span class="pg-provider__name">Jenkins</span><span class="pg-provider__count">31 checks</span></a>
  <a class="pg-provider" href="providers/circleci/"><span class="pg-provider__name">CircleCI</span><span class="pg-provider__count">30 checks</span></a>
  <a class="pg-provider" href="providers/cloudbuild/"><span class="pg-provider__name">Cloud Build</span><span class="pg-provider__count">9 checks</span></a>
</div>
</section>

<section class="pg-section">
<div class="pg-section__head">
<div class="pg-section__eyebrow">// flow</div>
<h2 class="pg-section__title">Inputs in. Graded report out.</h2>
<p class="pg-section__lede">A single scan path. Hover or tap any step for details.</p>
</div>

<ol class="pg-flow" role="list" aria-label="Scan pipeline steps">

  <li class="pg-flow__step">
    <button class="pg-flow__node" type="button" aria-describedby="flow-card-1">
      <span class="pg-flow__icon" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      </span>
      <span class="pg-flow__num">01</span>
      <span class="pg-flow__label">Input</span>
      <span class="pg-flow__sub">Repo or AWS account</span>
    </button>
    <div class="pg-flow__card" id="flow-card-1" role="tooltip">
      <div class="pg-flow__card-title">Input source</div>
      <p>The starting point is either a repository on disk or a live AWS account reached through the boto3 credential chain. No API tokens, no SaaS account.</p>
      <ul>
        <li>CI configs parsed from disk: GitHub, GitLab, Bitbucket, Azure DevOps, Jenkins, CircleCI, Cloud Build</li>
        <li>IaC plans: <code>terraform show -json</code> output, CloudFormation YAML/JSON</li>
        <li>Live AWS scan via standard AWS CLI profile / IAM role</li>
      </ul>
      <a class="pg-flow__link" href="usage/">Usage guide</a>
    </div>
  </li>

  <li class="pg-flow__step">
    <button class="pg-flow__node" type="button" aria-describedby="flow-card-2">
      <span class="pg-flow__icon" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      </span>
      <span class="pg-flow__num">02</span>
      <span class="pg-flow__label">Detect</span>
      <span class="pg-flow__sub">Provider</span>
    </button>
    <div class="pg-flow__card" id="flow-card-2" role="tooltip">
      <div class="pg-flow__card-title">Auto-detect</div>
      <p>The working directory is inspected and the matching provider is selected automatically — no flags required for the common case.</p>
      <ul>
        <li>Looks for <code>.github/workflows/</code>, <code>.gitlab-ci.yml</code>, <code>Jenkinsfile</code>, <code>cloudbuild.yaml</code>, <code>azure-pipelines.yml</code>, etc.</li>
        <li>Falls back to a live AWS scan when no CI config is found</li>
        <li>Override with <code>--pipeline &lt;name&gt;</code> to force a specific provider</li>
      </ul>
      <a class="pg-flow__link" href="providers/README/">All providers</a>
    </div>
  </li>

  <li class="pg-flow__step">
    <button class="pg-flow__node" type="button" aria-describedby="flow-card-3">
      <span class="pg-flow__icon" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      </span>
      <span class="pg-flow__num">03</span>
      <span class="pg-flow__label">Scan</span>
      <span class="pg-flow__sub">330+ checks</span>
    </button>
    <div class="pg-flow__card" id="flow-card-3" role="tooltip">
      <div class="pg-flow__card-title">Rule engine</div>
      <p>Every rule is a single Python module that consumes a parsed context (workflow YAML, Terraform plan, AWS resource catalog) and emits findings with severity, location, and suggested fix.</p>
      <ul>
        <li>Findings classified <strong>CRITICAL · HIGH · MEDIUM · LOW</strong></li>
        <li>Cross-provider primitives (shell-eval, lockfile-integrity, image-pinning) so a regex bug fixes itself everywhere</li>
        <li>68 rules ship autofixers — emit-or-apply</li>
      </ul>
      <a class="pg-flow__link" href="attack_chains/">Attack chains</a>
    </div>
  </li>

  <li class="pg-flow__step">
    <button class="pg-flow__node" type="button" aria-describedby="flow-card-4">
      <span class="pg-flow__icon" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </span>
      <span class="pg-flow__num">04</span>
      <span class="pg-flow__label">Map</span>
      <span class="pg-flow__sub">Standards</span>
    </button>
    <div class="pg-flow__card" id="flow-card-4" role="tooltip">
      <div class="pg-flow__card-title">Standards mapper</div>
      <p>Every finding is annotated with the controls it evidences across thirteen frameworks. Audit answers don't require leaving the tool.</p>
      <ul>
        <li>OWASP CI/CD Top 10 (full coverage)</li>
        <li>NIST SSDF (800-218), 800-53, 800-190, CSF 2.0</li>
        <li>SLSA Build Track v1.0, CIS, PCI DSS v4.0, ESF, OpenSSF Scorecard, S2C2F, SOC 2</li>
      </ul>
      <a class="pg-flow__link" href="standards/README/">Standards reference</a>
    </div>
  </li>

  <li class="pg-flow__step">
    <button class="pg-flow__node" type="button" aria-describedby="flow-card-5">
      <span class="pg-flow__icon" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
      </span>
      <span class="pg-flow__num">05</span>
      <span class="pg-flow__label">Score</span>
      <span class="pg-flow__sub">Grade + gate</span>
    </button>
    <div class="pg-flow__card" id="flow-card-5" role="tooltip">
      <div class="pg-flow__card-title">Score &amp; gate</div>
      <p>Findings are weighted (CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2) and converted to a 0–100 score with an <strong>A/B/C/D</strong> grade.</p>
      <ul>
        <li>Pass / fail thresholds: severity caps, max-failures, min-grade</li>
        <li>Baseline diff against a git ref so existing findings don't block</li>
        <li>Ignore file with expiries; autofix in CI with <code>--apply</code></li>
      </ul>
      <a class="pg-flow__link" href="ci_gate/">CI gate contract</a>
    </div>
  </li>

</ol>

<div class="pg-outputs">
  <div class="pg-outputs__head">
    <span class="pg-section__eyebrow">// outputs</span>
    <p class="pg-outputs__lede">Same findings, four shapes.</p>
  </div>
  <ul class="pg-outputs__grid" role="list">
    <li><a class="pg-output" href="output/#terminal"><strong>Terminal</strong><span>Rich color table for humans</span></a></li>
    <li><a class="pg-output" href="output/#json"><strong>JSON</strong><span>Machine-parseable for scripts</span></a></li>
    <li><a class="pg-output" href="output/#html"><strong>HTML report</strong><span>Client-side filters, shareable</span></a></li>
    <li><a class="pg-output" href="output/#sarif"><strong>SARIF 2.1.0</strong><span>GitHub code scanning, Defender</span></a></li>
  </ul>
</div>
</section>

<section class="pg-cta">
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
