# Security Policy

## Supported versions

Pipeline-Check follows semantic versioning. The public Python API
exported via ``pipeline_check.__all__`` is stable across minor releases
in the 1.x line; deeper imports under ``pipeline_check.core.*`` remain
internal.

Only the latest release published to
[PyPI](https://pypi.org/project/pipeline-check/) receives security fixes.
Older releases are not patched. Upgrade to the current 1.x release.

| Version | Supported |
| ------- | --------- |
| 1.x (latest) | Yes |
| < 1.0   | No (upgrade to 1.x) |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Use GitHub's private vulnerability reporting:

> [Report a vulnerability](https://github.com/dmartinochoa/pipeline-check/security/advisories/new)

Include, where possible:

- A description of the issue and its impact
- Steps to reproduce, or a minimal proof-of-concept
- The pipeline-check version (`pipeline_check --version`) and Python version
- Any suggested remediation

## What to expect

- **Acknowledgement:** within 7 days of your report.
- **Triage:** within 30 days, with a severity assessment and a rough fix timeline
  if the issue is accepted.
- **Disclosure:** coordinated through a GitHub Security Advisory once a fix
  ships. Reporters who wish to be named are credited in the advisory and the
  release notes.

There is no hard fix SLA — this is a solo-maintained open-source project — but
critical issues are prioritized over feature work.
