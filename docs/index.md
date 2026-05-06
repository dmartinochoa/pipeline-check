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
<span class="pg-hero__wordmark">pipeline-check · v{{ version }}</span>

# Catch supply-chain risks <span class="accent">before they ship.</span>

<p class="pg-hero__lede">
A read-only scanner for twelve providers — eleven file-based formats and
live AWS via boto3 — graded against the OWASP Top 10 CI/CD Risks plus
twelve compliance frameworks. Every finding ships with a control mapping
and a written remediation; 81 of the 430+ checks also emit a one-shot
patch you can apply with <code>--fix</code>.
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
<div class="pg-terminal__body"><span class="line l1"><span class="prompt">$</span> pipeline_check <span class="arg">--pipeline github</span></span><span class="line l2"> </span><span class="line l3"><span class="label">Pipeline-Check</span> v{{ version }} · scanning <span class="dim">.github/workflows/</span></span><span class="line l4"> </span><span class="line l5">  <span class="crit">CRITICAL</span>  GHA-001  Action not pinned to commit SHA</span><span class="line l6">            <span class="dim">.github/workflows/release.yml:14  uses: actions/checkout@v4</span></span><span class="line l7">  <span class="high">HIGH    </span>  GHA-016  Pipe-to-shell from untrusted host</span><span class="line l8">            <span class="dim">.github/workflows/build.yml:42  curl … | bash</span></span><span class="line l9">  <span class="med">MEDIUM  </span>  GHA-023  TLS verification disabled</span><span class="line l10">            <span class="dim">.github/workflows/deploy.yml:88  curl --insecure</span></span><span class="line l11">  <span class="low">LOW     </span>  GHA-015  No timeout-minutes on job <span class="dim">test</span></span><span class="line l12"> </span><span class="line l13"><span class="label">Score</span>  47 / 100   <span class="grade-d">Grade D</span></span><span class="line l14">        <span class="dim">2 critical · 4 high · 7 medium · 3 low</span></span><span class="line l15"> </span><span class="line l16"><span class="label">Standards</span>  OWASP CI/CD Top 10 · NIST SSDF · SLSA · CIS Supply Chain</span><span class="line l17"> </span><span class="line l18"><span class="ok">→</span> Fix suggestions written to <span class="dim">pipeline-check.sarif</span></span><span class="line l19"><span class="ok">→</span> Run with <span class="dim">--apply</span> to autofix 4 of 16 findings.<span class="pg-cursor"></span></span></div>
</div>

</div>
</section>

<section class="pg-stats">
<div class="pg-stats__inner">
  <div class="pg-stat"><div class="pg-stat__num">430+</div><div class="pg-stat__label">Checks</div></div>
  <div class="pg-stat"><div class="pg-stat__num">12</div><div class="pg-stat__label">Providers</div></div>
  <div class="pg-stat"><div class="pg-stat__num">13</div><div class="pg-stat__label">Compliance standards</div></div>
  <div class="pg-stat"><div class="pg-stat__num">81</div><div class="pg-stat__label">Autofixers</div></div>
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
<a class="pg-feature__link" href="standards/owasp_cicd_top_10/">Read OWASP coverage</a>
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
to force one. Counts reflect the current rule catalog.
</p>
</div>

<div class="pg-providers">
  <a class="pg-provider" href="providers/aws/"><span class="pg-provider__name">AWS</span><span class="pg-provider__count">71 checks</span></a>
  <a class="pg-provider" href="providers/terraform/"><span class="pg-provider__name">Terraform</span><span class="pg-provider__count">aws-parity</span></a>
  <a class="pg-provider" href="providers/cloudformation/"><span class="pg-provider__name">CloudFormation</span><span class="pg-provider__count">~63 checks</span></a>
  <a class="pg-provider" href="providers/github/"><span class="pg-provider__name">GitHub Actions</span><span class="pg-provider__count">33 checks</span></a>
  <a class="pg-provider" href="providers/gitlab/"><span class="pg-provider__name">GitLab CI</span><span class="pg-provider__count">31 checks</span></a>
  <a class="pg-provider" href="providers/bitbucket/"><span class="pg-provider__name">Bitbucket</span><span class="pg-provider__count">28 checks</span></a>
  <a class="pg-provider" href="providers/azure/"><span class="pg-provider__name">Azure DevOps</span><span class="pg-provider__count">29 checks</span></a>
  <a class="pg-provider" href="providers/jenkins/"><span class="pg-provider__name">Jenkins</span><span class="pg-provider__count">31 checks</span></a>
  <a class="pg-provider" href="providers/circleci/"><span class="pg-provider__name">CircleCI</span><span class="pg-provider__count">31 checks</span></a>
  <a class="pg-provider" href="providers/cloudbuild/"><span class="pg-provider__name">Cloud Build</span><span class="pg-provider__count">18 checks</span></a>
  <a class="pg-provider" href="providers/dockerfile/"><span class="pg-provider__name">Dockerfile</span><span class="pg-provider__count">16 checks</span></a>
  <a class="pg-provider" href="providers/kubernetes/"><span class="pg-provider__name">Kubernetes</span><span class="pg-provider__count">26 checks</span></a>
</div>
</section>

<section class="pg-section" markdown>
<div class="pg-section__head" markdown>
<div class="pg-section__eyebrow">// flow</div>
<h2 class="pg-section__title">Inputs in. Graded report out.</h2>
<p class="pg-section__lede">Hover any node for a quick description; click to jump to its reference page.</p>
</div>

```mermaid
flowchart LR
    A[Repo or AWS account] -->|auto-detect| B[Provider]
    B --> C[Rule engine<br/>430+ checks]
    C --> D[Standards mapper<br/>OWASP · NIST · SLSA · …]
    D --> E[Scorer<br/>A/B/C/D]
    E --> F1[Terminal]
    E --> F2[JSON]
    E --> F3[HTML report]
    E --> F4[SARIF 2.1.0]
    E --> G{CI gate}
    G -->|pass| H[Merge]
    G -->|fail| I[Block + report]

    click A "usage/" "Repo on disk or live AWS account — no API tokens, no SaaS"
    click B "providers/" "Auto-detected from cwd; override with --pipeline NAME"
    click C "attack_chains/" "430+ rules emit findings with severity, location, fix"
    click D "standards/" "Findings mapped to OWASP, NIST SSDF, SLSA, CIS, …"
    click E "scoring_model/" "Severity-weighted 0–100 score with an A/B/C/D grade"
    click F1 "output/#terminal" "Rich color table for humans"
    click F2 "output/#json" "Machine-parseable JSON for scripts"
    click F3 "output/#html" "HTML report with client-side filters"
    click F4 "output/#sarif" "SARIF 2.1.0 for GitHub code scanning, Defender for DevOps"
    click G "ci_gate/" "Severity caps, baseline diff, ignore file — pass/fail contract"
    click H "ci_gate/" "Severity below thresholds, exit 0"
    click I "ci_gate/" "Severity above threshold; non-zero exit + report (--fix patches the subset that has a fixer)"

    classDef src      fill:#0b3954,stroke:#1ba3a9,stroke-width:1.5px,color:#e7eef5;
    classDef step     fill:#134e6f,stroke:#1ba3a9,stroke-width:1.5px,color:#e7eef5;
    classDef out      fill:#087e8b,stroke:#6dd5ed,stroke-width:1.5px,color:#fff;
    classDef gate     fill:#0b3954,stroke:#f4a261,stroke-width:2px,color:#f4a261;
    classDef pass     fill:#2a9d8f,stroke:#2a9d8f,stroke-width:1.5px,color:#fff;
    classDef fail     fill:#bf1363,stroke:#bf1363,stroke-width:1.5px,color:#fff;

    class A src;
    class B,C,D,E step;
    class F1,F2,F3,F4 out;
    class G gate;
    class H pass;
    class I fail;
```

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
