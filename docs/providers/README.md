# Providers

A **provider** binds a CI/CD platform to the scanner: it builds the API
context (credentials, clients) and declares which check modules run against
it. The scanner's core is provider-agnostic — adding a new platform never
requires editing `Scanner`, `Reporter`, or the CLI.

## Supported providers

| Name        | Status | Context                                                 | Docs                           |
|-------------|--------|---------------------------------------------------------|--------------------------------|
| `aws`       | stable | `boto3.Session` — live AWS account                      | [aws.md](aws.md)               |
| `terraform` | stable | `TerraformContext` — parsed `terraform show -json` plan | [terraform.md](terraform.md)   |
| `github`    | stable | `GitHubContext` — parsed GitHub Actions workflow YAML   | [github.md](github.md)         |
| `gitlab`    | stable | `GitLabContext` — parsed `.gitlab-ci.yml`               | [gitlab.md](gitlab.md)         |
| `bitbucket` | stable | `BitbucketContext` — parsed `bitbucket-pipelines.yml`   | [bitbucket.md](bitbucket.md)   |
| `azure`     | stable | `AzureContext` — parsed `azure-pipelines.yml`           | [azure.md](azure.md)           |

## Adding a new provider

1. Create `pipeline_check/core/providers/<name>.py` subclassing `BaseProvider`.
2. Set `NAME`, implement `build_context(**kwargs)` and `check_classes`.
3. Register it in `pipeline_check/core/providers/__init__.py`.
4. Add check modules under `pipeline_check/core/checks/<name>/` and tests
   under `tests/<name>/`.
5. (Optional) Add compliance mappings for the new check IDs in
   `pipeline_check/core/standards/data/*.py`.

The `Scanner`, `--pipeline` CLI flag, and provider registry pick it up
automatically.
