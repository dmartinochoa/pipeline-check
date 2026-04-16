# SLSA Build Track v1.0

- **Version:** 1.0
- **URL:** https://slsa.dev/spec/v1.0/
- **Scope:** Build track requirements (L1–L3). The Source and
  Dependency tracks require SCM and registry introspection that this
  scanner does not perform.

## Requirements evidenced

| Control                   | Description                                                              |
|---------------------------|--------------------------------------------------------------------------|
| Build.L1.Scripted         | Build process is fully defined and automated                             |
| Build.L1.Provenance       | Provenance describing how the artifact was produced is generated         |
| Build.L2.Hosted           | Builds run on a hosted build platform, not a developer workstation       |
| Build.L2.Signed           | Provenance is authenticated and cannot be forged by tenants              |
| Build.L3.Isolated         | Build runs in an isolated environment not influenced by other builds     |
| Build.L3.Ephemeral        | Build environment is ephemeral and provisioned fresh for each run        |
| Build.L3.NonFalsifiable   | Provenance cannot be falsified by the build's own tenant                 |

## Not covered

- **Source track** (branch protection, 2-reviewer, retained history) —
  requires GitHub/GitLab policy inspection beyond Actions workflows.
- **Dependency track** — requires package-manifest and lockfile
  analysis across the dependency graph.
