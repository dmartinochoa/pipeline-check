"""Generate provider reference documentation from the rule registry.

Before this existed, ``docs/providers/<provider>.md`` was a
hand-maintained markdown file that duplicated rule metadata
(check IDs, titles, severities, recommendations) already declared
in Python. The parallel state rotted: a new check meant edits in
three places (the check class, the standards mapping, and the doc)
and any of them could drift.

With the per-rule-module refactor (see
``pipeline_check/core/checks/<provider>/rules/``), every rule
exports a ``RULE`` object carrying its metadata plus prose fields
(``recommendation``, ``docs_note``). This script walks that
registry and writes a fully-derived provider doc — the code is
the source of truth and the doc can never drift.

Usage
-----
    python scripts/gen_provider_docs.py           # write every supported provider
    python scripts/gen_provider_docs.py github    # write just one provider

All five workflow providers (github, gitlab, bitbucket, azure,
jenkins) are supported.
"""
from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

# Make ``pipeline_check`` importable when the script is run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from pipeline_check.core.checks.rule import Rule, discover_rules

# ``provider_slug -> (display_title, rules_package_fqn, docs_output_path,
#                     per-provider header markdown)``
SUPPORTED_PROVIDERS: dict[str, tuple[str, str, Path, str]] = {
    "github": (
        "GitHub Actions",
        "pipeline_check.core.checks.github.rules",
        _REPO_ROOT / "docs" / "providers" / "github.md",
        """\
# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory — no
network calls, no GitHub API token, no installed Actions runner required.

## Producer workflow

```bash
# --gha-path is auto-detected when .github/workflows exists at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline github

# …or pass it explicitly.
pipeline_check --pipeline github --gha-path .github/workflows
```

A single workflow file can also be passed directly:

```bash
pipeline_check --pipeline github --gha-path .github/workflows/release.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS and Terraform providers.
""",
    ),
    "gitlab": (
        "GitLab CI",
        "pipeline_check.core.checks.gitlab.rules",
        _REPO_ROOT / "docs" / "providers" / "gitlab.md",
        """\
# GitLab CI provider

Parses `.gitlab-ci.yml` on disk — no GitLab API token, no runner install.
Works against the file in a detached clone or a merged-result pipeline
export.

## Producer workflow

```bash
# --gitlab-path auto-detected when .gitlab-ci.yml exists at cwd.
pipeline_check --pipeline gitlab

# …or pass it explicitly (file or directory).
pipeline_check --pipeline gitlab --gitlab-path ci/
```
""",
    ),
    "bitbucket": (
        "Bitbucket Pipelines",
        "pipeline_check.core.checks.bitbucket.rules",
        _REPO_ROOT / "docs" / "providers" / "bitbucket.md",
        """\
# Bitbucket Pipelines provider

Parses `bitbucket-pipelines.yml` on disk — no Bitbucket API token, no
runner install.

## Producer workflow

```bash
# --bitbucket-path auto-detected when bitbucket-pipelines.yml exists at cwd.
pipeline_check --pipeline bitbucket

# …or pass it explicitly (file or directory).
pipeline_check --pipeline bitbucket --bitbucket-path ci/
```
""",
    ),
    "azure": (
        "Azure DevOps Pipelines",
        "pipeline_check.core.checks.azure.rules",
        _REPO_ROOT / "docs" / "providers" / "azure.md",
        """\
# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk — no network calls, no ADO
personal access token.

## Producer workflow

```bash
# --azure-path is auto-detected when azure-pipelines.yml is present at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline azure

# …or pass it explicitly.
pipeline_check --pipeline azure --azure-path azure-pipelines.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Shape coverage

The walker handles every layout ADO supports:

- Flat single-job pipeline — top-level `steps:`
- Single-stage multi-job — top-level `jobs:`
- Multi-stage — `stages: → jobs: → steps:`
- Deployment jobs — steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.
""",
    ),
    "jenkins": (
        "Jenkins",
        "pipeline_check.core.checks.jenkins.rules",
        _REPO_ROOT / "docs" / "providers" / "jenkins.md",
        """\
# Jenkins provider

Parses Jenkinsfile text — Declarative or Scripted Pipeline — without
talking to a Jenkins controller. No Groovy interpreter, no plugin
install, no API token.

## Producer workflow

```bash
# --jenkinsfile-path is auto-detected when ./Jenkinsfile exists at cwd.
pipeline_check --pipeline jenkins

# …or pass it explicitly.
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile

# Scan a directory of multiple Jenkinsfiles (e.g. monorepo with per-app pipelines).
pipeline_check --pipeline jenkins --jenkinsfile-path ci/
```

The loader recognises files named `Jenkinsfile` exactly, plus anything
ending in `.jenkinsfile` or `.groovy`. It treats every file as text —
no Groovy parsing — and applies the same regex-driven heuristics the
other workflow providers use for `run:` blocks. False positives are
intentional: better to flag and let the operator suppress than to
miss a real injection because the parser couldn't follow a dynamic
expression.
""",
    ),
    "circleci": (
        "CircleCI",
        "pipeline_check.core.checks.circleci.rules",
        _REPO_ROOT / "docs" / "providers" / "circleci.md",
        """\
# CircleCI provider

Parses `.circleci/config.yml` on disk — no CircleCI API token, no
runner install.

## Producer workflow

```bash
# --circleci-path is auto-detected when .circleci/config.yml exists at cwd.
pipeline_check --pipeline circleci

# …or pass it explicitly.
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### CircleCI-specific checks

Several checks target CircleCI concepts that have no direct analogue
in other providers:

- **CC-001** — orb version pinning (`@volatile`, `@1` → `@5.1.0`)
- **CC-009** — approval gate via `type: approval` predecessor job
- **CC-012** — dynamic config generation via `setup: true`
- **CC-019** — `add_ssh_keys` fingerprint restriction
""",
    ),
    "cloudbuild": (
        "Google Cloud Build",
        "pipeline_check.core.checks.cloudbuild.rules",
        _REPO_ROOT / "docs" / "providers" / "cloudbuild.md",
        """\
# Google Cloud Build provider

Parses `cloudbuild.yaml` on disk — no Google Cloud credentials, no
`gcloud` install, no Cloud Build API token required. Each document
must declare a top-level `steps:` list; files without it (SAM
templates, ordinary YAML configs) are skipped by the loader.

## Producer workflow

```bash
# --cloudbuild-path is auto-detected when cloudbuild.yaml/cloudbuild.yml
# exists at cwd.
pipeline_check --pipeline cloudbuild

# …or pass it explicitly.
pipeline_check --pipeline cloudbuild --cloudbuild-path ci/cloudbuild.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Cloud Build-specific checks

Several checks target Cloud Build concepts that have no direct
analogue in other providers:

- **GCB-002** — `serviceAccount:` must be set; the default Cloud Build
  SA is typically broader than any single pipeline needs.
- **GCB-003** — secrets must flow through `availableSecrets.secret
  Manager[].env` + `secretEnv:`, never via inline `gcloud secrets
  versions access` in `args`.
- **GCB-004** — `options.dynamicSubstitutions: true` combined with a
  user-substitution (`$_FOO`) in step args opens a trigger-editor-
  controlled shell-injection path.
""",
    ),
    "kubernetes": (
        "Kubernetes",
        "pipeline_check.core.checks.kubernetes.rules",
        _REPO_ROOT / "docs" / "providers" / "kubernetes.md",
        """\
# Kubernetes manifest provider

Parses Kubernetes API documents (`apiVersion:` + `kind:`) from `.yaml`
/ `.yml` files on disk — text-only static analysis. No `kubectl`, no
cluster access, no Helm or Kustomize rendering. Multi-document YAML
(`---`-separated) is fully supported; each document is parsed into
its own `Manifest` record.

Helm chart values, kustomization base files, and other YAML that
doesn't carry the canonical `apiVersion` + `kind` shape are silently
skipped, so a directory mixing manifests with `Chart.yaml` /
`values.yaml` / `kustomization.yaml` won't trip the loader.

## Producer workflow

```bash
# --k8s-path is auto-detected when ./kubernetes/, ./k8s/, or
# ./manifests/ exist at cwd.
pipeline_check --pipeline kubernetes

# …or pass it explicitly (file or directory).
pipeline_check --pipeline kubernetes --k8s-path k8s/

# A single multi-document manifest works too.
pipeline_check --pipeline kubernetes --k8s-path deploy.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Workload coverage

The walker recognises every kind that carries a pod spec:

- `Pod` — pod spec at `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job`
  — pod spec at `spec.template.spec`
- `CronJob` — pod spec at `spec.jobTemplate.spec.template.spec`

Container-level rules walk all three container lists (`containers`,
`initContainers`, `ephemeralContainers`), so init-time and ephemeral
debug containers are covered along with the long-lived workload.

### RBAC and Service rules

Four rules target non-workload kinds:

- **K8S-018** — `Kind: Secret` carrying credential-shaped literals
  in `stringData` or `data`. Base64 values in `data:` are decoded
  and re-checked for AKIA-shaped AWS keys.
- **K8S-020** — `ClusterRoleBinding` to `cluster-admin`, `admin`,
  or `system:masters`.
- **K8S-021** — `Role` / `ClusterRole` granting wildcard verbs+
  resources (both `verbs: ["*"]` and `resources: ["*"]`).
- **K8S-022** — `Service` exposing port 22 (SSH).
""",
    ),
    "dockerfile": (
        "Dockerfile",
        "pipeline_check.core.checks.dockerfile.rules",
        _REPO_ROOT / "docs" / "providers" / "dockerfile.md",
        """\
# Dockerfile provider

Parses `Dockerfile` / `Containerfile` documents on disk — text-only
static analysis, no image build, no registry pull, no daemon access.
Multi-stage builds are flattened: rules see the full instruction
stream and decide for themselves whether to scope by stage (e.g.
DF-002 only checks the *final* stage's `USER`).

## Producer workflow

```bash
# --dockerfile-path is auto-detected when Dockerfile/Containerfile
# exists at cwd.
pipeline_check --pipeline dockerfile

# …or pass it explicitly.
pipeline_check --pipeline dockerfile --dockerfile-path docker/api.Dockerfile

# Recursively scan a service directory containing many per-service
# Dockerfiles. The loader matches Dockerfile, Containerfile,
# Dockerfile.<suffix>, and *.Dockerfile by default.
pipeline_check --pipeline dockerfile --dockerfile-path services/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Dockerfile-specific checks

Several checks target Dockerfile concepts that have no direct
analogue in other providers:

- **DF-001** — `FROM` must pin by `@sha256:<digest>`. Reuses the same
  classifier as GL-001 / JF-009 / ADO-009 / CC-003 so the
  floating-tag vocabulary matches across the tool.
- **DF-002** — final stage must run as a non-root `USER`. Multi-stage
  builds: only the runtime image's identity matters, so this rule
  scopes USER tracking to the directives after the *last* `FROM`.
- **DF-003** — `ADD <url>` must carry a BuildKit `--checksum=sha256:`
  flag, otherwise it pulls remote content with no integrity check.
- **DF-006** — `ENV` / `ARG` values are baked into image layers;
  ``docker history`` reads them even after they're overwritten. Any
  literal credential-shaped value (AKIA-prefixed, or a key named
  `*_PASSWORD` / `*_TOKEN` / `*_SECRET` with a non-empty literal) is
  CRITICAL.
""",
    ),
}


_FOOTER_TEMPLATE = """\
---

## Adding a new {title} check

1. Create a new module at
   `pipeline_check/core/checks/{pkg}/rules/{prefix_lc}NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/{pkg}/{prefix}-NNN.{{unsafe,safe}}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py {slug}
   ```
"""


_FOOTER_CONFIG: dict[str, dict[str, str]] = {
    "github":    {"prefix": "GHA", "prefix_lc": "gha", "pkg": "github"},
    "gitlab":    {"prefix": "GL",  "prefix_lc": "gl",  "pkg": "gitlab"},
    "bitbucket": {"prefix": "BB",  "prefix_lc": "bb",  "pkg": "bitbucket"},
    "azure":     {"prefix": "ADO", "prefix_lc": "ado", "pkg": "azure"},
    "jenkins":   {"prefix": "JF",  "prefix_lc": "jf",  "pkg": "jenkins"},
    "circleci":  {"prefix": "CC",  "prefix_lc": "cc",  "pkg": "circleci"},
    "cloudbuild": {"prefix": "GCB", "prefix_lc": "gcb", "pkg": "cloudbuild"},
    "dockerfile": {"prefix": "DF",  "prefix_lc": "df",  "pkg": "dockerfile"},
    "kubernetes": {"prefix": "K8S", "prefix_lc": "k8s", "pkg": "kubernetes"},
}


def _render_provider(title: str, header: str, rules_fqn: str, slug: str = "") -> str:
    """Walk the rule registry and stitch together the full provider doc."""
    pairs = discover_rules(rules_fqn)
    lines: list[str] = [header.rstrip() + "\n\n"]

    # ── Summary table ──
    # Each check ID links to the per-rule section further down via a
    # pinned attr-list anchor (``{ #gha-001 }``) on the rendered H2.
    # The severity column emits a color-coded chip so the table
    # doubles as a click-through priority list.
    lines.append("## What it covers\n\n")
    lines.append("| Check | Title | Severity |\n")
    lines.append("|-------|-------|----------|\n")
    for rule, _ in pairs:
        anchor = _rule_anchor(rule.id)
        sev_chip = _severity_chip(rule.severity.value)
        lines.append(
            f"| [{rule.id}](#{anchor}) | {rule.title} | {sev_chip} |\n"
        )
    lines.append("\n---\n\n")

    # ── Per-rule section ──
    for rule, _ in pairs:
        lines.append(_render_rule(rule))

    footer_cfg = _FOOTER_CONFIG.get(slug, {"prefix": "", "prefix_lc": "", "pkg": slug})
    lines.append(_FOOTER_TEMPLATE.format(title=title, slug=slug, **footer_cfg))
    return "".join(lines)


def _rule_anchor(rule_id: str) -> str:
    """Stable in-page anchor for a rule_id.

    Pinned via ``attr_list`` ``{ #gha-001 }`` on the H2, so the slug
    is deterministic regardless of the title text or its punctuation.
    Markdown's default ``toc`` slugifier would strip the em-dash and
    derive the slug from the title — fine, but couples the anchor to
    the wording. A pinned ID survives title rephrases.
    """
    return rule_id.lower()


def _severity_chip(severity: str) -> str:
    """HTML chip used in summary tables. Uses a CSS class per severity
    so the color is theme-aware (different on light vs slate)."""
    sev_lc = severity.lower()
    return f'<span class="pg-sev pg-sev--{sev_lc}">{severity}</span>'


def _render_rule(rule: Rule) -> str:
    """Render one rule as a card-style section with severity rail.

    Output shape (renders in MkDocs' ``md_in_html`` extension; the
    ``markdown`` attribute lets nested markdown inside the
    ``<div>`` cascades work as expected):

        <div class="pg-rule pg-rule--high" markdown>

        ## GHA-001 — title { #gha-001 }

        <div class="pg-rule__tags">…severity chip + tag pills…</div>

        Body text (docs_note prose).

        <div class="pg-rule__rec" markdown>
        **Recommended action**
        …recommendation prose…
        </div>

        </div>

    The CSS picks up ``pg-rule--<severity>`` to color the left
    rail, the chip, and the recommendation block accent.
    """
    parts: list[str] = []
    anchor = _rule_anchor(rule.id)
    sev = rule.severity.value
    sev_lc = sev.lower()

    parts.append(f'<div class="pg-rule pg-rule--{sev_lc}" markdown>\n\n')
    parts.append(f"## {rule.id} — {rule.title} {{ #{anchor} }}\n\n")

    # ── Tag chip row: severity + OWASP + ESF + CWE ──
    chips: list[str] = [_severity_chip(sev)]
    for tag in rule.owasp:
        chips.append(f'<span class="pg-tag pg-tag--owasp">{tag}</span>')
    for tag in rule.esf:
        chips.append(f'<span class="pg-tag pg-tag--esf">{tag}</span>')
    for tag in rule.cwe:
        chips.append(f'<span class="pg-tag pg-tag--cwe">{tag}</span>')
    parts.append('<div class="pg-rule__tags">\n')
    parts.append(" ".join(chips) + "\n")
    parts.append("</div>\n\n")

    # ── Body — the rule's ``docs_note`` is the "why this matters"
    # narrative; render as plain prose. ──
    if rule.docs_note:
        parts.append(rule.docs_note.strip() + "\n\n")

    # ── Recommendation: framed block so it stands out from the body
    # narrative. Marked with ``markdown`` so embedded code blocks /
    # bullet lists in the recommendation render. ──
    if rule.recommendation:
        parts.append('<div class="pg-rule__rec" markdown>\n\n')
        parts.append("**Recommended action**\n\n")
        parts.append(rule.recommendation.strip() + "\n\n")
        parts.append("</div>\n\n")

    parts.append("</div>\n\n")
    return "".join(parts)


def _providers_to_render(argv: Iterable[str]) -> list[str]:
    argv = list(argv)
    if not argv:
        return list(SUPPORTED_PROVIDERS.keys())
    for name in argv:
        if name not in SUPPORTED_PROVIDERS:
            raise SystemExit(
                f"Unknown provider {name!r}. "
                f"Supported: {', '.join(SUPPORTED_PROVIDERS.keys())}"
            )
    return argv


def main(argv: Iterable[str] | None = None) -> None:
    targets = _providers_to_render(argv if argv is not None else sys.argv[1:])
    for slug in targets:
        title, rules_fqn, out_path, header = SUPPORTED_PROVIDERS[slug]
        body = _render_provider(title, header, rules_fqn, slug)
        out_path.write_text(body, encoding="utf-8")
        print(f"[gen-docs] wrote {out_path.relative_to(_REPO_ROOT)} "
              f"({body.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
