# Pipeline-Check

**Find security risks in your CI/CD pipelines before attackers do.**

A read-only scanner for **19 CI/CD and infrastructure providers**, mapped to
**14 compliance standards**, with **590+ checks** and **111 autofixers**.
Every finding maps to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/),
SLSA, NIST SSDF, PCI DSS, SOC 2, and nine more frameworks. Each scan is
graded **A through D** so you can gate merges on the result.

- **Repo:** https://github.com/dmartinochoa/pipeline-check
- **Docs:** https://dmartinochoa.github.io/pipeline-check/
- **PyPI:** [`pip install pipeline-check`](https://pypi.org/project/pipeline-check/)

## Quick start

The image working directory is `/scan`. Bind-mount your repo there and
auto-detect handles the rest:

```bash
docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check
```

Pass any CLI flag after the image reference:

```bash
docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check \
  --pipeline github --output sarif --output-file pipeline-check.sarif

docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check \
  --pipelines github,dockerfile,kubernetes --fail-on HIGH
```

For live AWS scans, pass through your credentials:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_REGION \
  dmartinochoa/pipeline-check --pipeline aws
```

## Tags

| Tag | Points to |
|-----|-----------|
| `latest` | most recent release on `master` |
| `<version>` (e.g. `0.5.0`) | a specific release |
| `sha-<short>` | a specific commit build, for digest-style pinning |

The same digest is published to GHCR at
`ghcr.io/dmartinochoa/pipeline-check` — pick whichever registry your
platform already pulls from. For air-gapped or supply-chain-locked
environments, pin by digest (`@sha256:...`) rather than tag.

## Image facts

- **Multi-arch:** `linux/amd64` + `linux/arm64`
- **Base:** `python:3.12-slim` (Debian 13)
- **Provenance:** SLSA Build L3 attestation attached to the manifest
- **SBOM:** CycloneDX SBOM attached to the manifest
- **Non-root:** runs as UID 1000 (`scanner`)

## What it scans

**CI/CD platforms:** GitHub Actions, GitLab CI, Jenkins, CircleCI,
Azure DevOps, Bitbucket Pipelines, Buildkite, Drone, Tekton, Argo
Workflows, Google Cloud Build.

**Infrastructure:** Terraform plans, CloudFormation, Kubernetes
manifests, Helm charts, Dockerfile / Containerfile, OCI image
manifests.

**Live cloud:** AWS accounts via the boto3 credential chain (no token
needed inside the image; pass credentials at run time).

**SCM posture:** GitHub, GitLab, and Bitbucket repo governance via
each platform's REST API.

Each provider checks dependency pinning, script injection, credential
leaks, deploy approval gates, artifact signing, SBOM generation,
container hardening, package integrity, timeout enforcement,
vulnerability scanning, and TLS verification. A dataflow taint engine
catches multi-step and cross-job propagation that single-rule scanners
miss, and **36 attack chains** correlate findings into MITRE ATT&CK-mapped
kill chains.

## Use in CI

GitHub Actions, container-only flow (no `pip install` step needed):

```yaml
- name: Pipeline-Check scan
  run: |
    docker run --rm \
      -v "${{ github.workspace }}:/scan" \
      dmartinochoa/pipeline-check:latest \
      --pipeline github \
      --output sarif --output-file pipeline-check.sarif \
      --fail-on HIGH
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pipeline-check.sarif
```

GitLab CI:

```yaml
security-scan:
  image: dmartinochoa/pipeline-check:latest
  script:
    - pipeline_check --pipeline gitlab --fail-on HIGH --output json > report.json
  artifacts:
    reports:
      sast: report.json
```

## License

MIT. See the [LICENSE](https://github.com/dmartinochoa/pipeline-check/blob/master/LICENSE)
file in the repo.
