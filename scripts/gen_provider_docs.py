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

Currently only providers that have been migrated to the per-rule-
module layout (github) are supported. Other providers keep their
hand-maintained docs until their check classes are split too.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

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
}


def _render_provider(title: str, header: str, rules_fqn: str, slug: str = "") -> str:
    """Walk the rule registry and stitch together the full provider doc."""
    pairs = discover_rules(rules_fqn)
    lines: list[str] = [header.rstrip() + "\n\n"]

    # ── Summary table ──
    lines.append("## What it covers\n\n")
    lines.append("| Check | Title | Severity |\n")
    lines.append("|-------|-------|----------|\n")
    for rule, _ in pairs:
        lines.append(f"| {rule.id} | {rule.title} | {rule.severity.value} |\n")
    lines.append("\n---\n\n")

    # ── Per-rule section ──
    for rule, _ in pairs:
        lines.append(_render_rule(rule))

    footer_cfg = _FOOTER_CONFIG.get(slug, {"prefix": "", "prefix_lc": "", "pkg": slug})
    lines.append(_FOOTER_TEMPLATE.format(title=title, slug=slug, **footer_cfg))
    return "".join(lines)


def _render_rule(rule: Rule) -> str:
    """Render one ``## GHA-001 — <title>`` section."""
    parts: list[str] = []
    parts.append(f"## {rule.id} — {rule.title}\n")
    sev_line = f"**Severity:** {rule.severity.value}"
    if rule.owasp:
        sev_line += " · OWASP " + ", ".join(rule.owasp)
    if rule.esf:
        sev_line += " · ESF " + ", ".join(rule.esf)
    parts.append(sev_line + "\n\n")
    if rule.docs_note:
        parts.append(rule.docs_note.strip() + "\n\n")
    if rule.recommendation:
        parts.append("**Recommended action**\n\n")
        parts.append(rule.recommendation.strip() + "\n\n")
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
