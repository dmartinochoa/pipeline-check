# SCM posture

Category landing page for the SCM (source control management)
posture providers. These providers scan repository governance via
each platform's REST API: branch protection, required reviews,
code scanning, secret scanning, signed commits, and the rest of
the controls that live at the repo / org settings layer rather than
in workflow YAML. Each rule maps to the OpenSSF Scorecard check it
evidences and to the CIS Software Supply Chain Security Guide
section it satisfies.

The home page shows one "SCM posture" tile that aggregates the
rule count across all platforms; the per-platform pages below
carry the full rule reference and token-permission tables.

## Platforms in this category

<div class="pg-doc-cards">
  <a class="pg-doc-card" href="../scm_github/">
    <h3>GitHub</h3>
    <p>Full 49-rule pack. Branch protection, rulesets, security features, environments, deploy keys, webhooks, outside collaborators, Actions permissions.</p>
    <span class="pg-doc-card__meta">{{ providers.scm.checks }}</span>
  </a>
  <a class="pg-doc-card" href="../scm_gitlab/">
    <h3>GitLab</h3>
    <p>Seven universal rules: branch protection, required reviews, signed commits, force-push, status checks, branch deletion, CODEOWNERS.</p>
    <span class="pg-doc-card__meta">7 checks (universal subset)</span>
  </a>
  <a class="pg-doc-card" href="../scm_bitbucket/">
    <h3>Bitbucket Cloud</h3>
    <p>Seven universal rules: branch restrictions, required approvals, force-push, passing builds, branch deletion, CODEOWNERS.</p>
    <span class="pg-doc-card__meta">7 checks (universal subset)</span>
  </a>
</div>

## What the platforms share

Seven rules run identically on every platform:

| Rule | What it checks |
|------|----------------|
| SCM-001 | Default branch has no protection rule |
| SCM-002 | No required pull request reviews |
| SCM-006 | No signed-commit requirement |
| SCM-007 | Force-pushes allowed |
| SCM-008 | No required status checks |
| SCM-009 | Branch deletion allowed |
| SCM-017 | No CODEOWNERS file |

GitHub-only rules (SCM-003..005, SCM-010..016, SCM-018..049) pass
on GitLab and Bitbucket with a "not applicable on PLATFORM" note
so the operator sees the deliberate skip rather than a silent
absence.

## Offline / fixture mode

``--scm-fixture-dir DIR`` reads JSON responses from disk instead of
hitting the network on every platform. No token is required and no
HTTP traffic leaves the host. Useful for CI runs, air-gapped
evaluation, and reproducing a customer's posture against a captured
fixture set. Endpoint paths map to
``<endpoint-with-slashes-as-underscores>.json`` under DIR; a
missing file is treated as a 404 (the rule passes silently with an
unavailability note, same as when a real call fails).

## CLI

```bash
pipeline_check --pipeline scm --scm-platform github  --scm-repo octocat/hello-world
pipeline_check --pipeline scm --scm-platform gitlab  --scm-repo group/subgroup/project
pipeline_check --pipeline scm --scm-platform bitbucket --scm-repo acme/widget
```

See each per-platform page for the full rule reference, token
requirements, and platform-specific behavior notes.
