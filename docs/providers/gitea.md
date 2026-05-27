# Gitea / Forgejo Actions provider

Gitea Actions and Forgejo Actions use the same workflow YAML syntax
as GitHub Actions, stored under ``.gitea/workflows/`` or
``.forgejo/workflows/``. This provider reuses the full
[GitHub Actions](github.md) rule pack (``GHA-*`` IDs). GitHub-specific
reputation rules (GHA-041..043, GHA-089..091, GHA-096) that depend on
``--resolve-remote`` and GitHub API metadata pass silently when that
data is absent.

## Producer workflow

```bash
# Point at the workflow directory.
pipeline_check --pipeline gitea --gitea-path .gitea/workflows

# Forgejo uses the same engine.
pipeline_check --pipeline gitea --gitea-path .forgejo/workflows
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the GitHub Actions provider.

## Rule coverage

This provider runs the same rule pack as the
[GitHub Actions provider](github.md). See that page for the full
rule reference, severity table, and per-rule documentation.
