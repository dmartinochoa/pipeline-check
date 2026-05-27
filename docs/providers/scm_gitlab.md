# SCM posture: GitLab

Scans GitLab project governance via the REST API. Runs the seven
universal SCM rules shared across all platforms. GitHub-only rules
(SCM-003..005, SCM-010..016, SCM-018..049) pass silently with a
"not applicable on gitlab" note.

See the [SCM posture overview](scm.md) for shared concepts and the
[GitHub page](scm_github.md) for the full rule reference.

## Producer workflow

```bash
# Token comes from --gh-token (the flag is shared across
# platforms) or $GITLAB_TOKEN; needs the ``read_api`` scope. Repo
# spec is the full project path (nested subgroups allowed).
pipeline_check --pipeline scm --scm-platform gitlab \
    --scm-repo group/subgroup/project

# Offline / CI mode: read JSON responses from disk.
pipeline_check --pipeline scm --scm-platform gitlab \
    --scm-repo group/subgroup/project \
    --scm-fixture-dir ./scm-fixtures/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

## Token permissions

| Tier | GitLab token scope | Rules unlocked |
|------|--------------------|----------------|
| public (no token) | — | SCM-001, -002, -006, -007, -008, -009, -017 on public projects only |
| read | ``read_api`` | full universal-rule coverage on private projects (and the rate-limit raise) |
| maintainer-equivalent | ``read_api`` issued by a project Maintainer (or higher) | adds SCM-006's ``push_rules.reject_unsigned_commits`` signal (the push-rules endpoint is gated on Maintainer access to the project) |

## Per-rule behavior

  * **SCM-001 / SCM-007 / SCM-009** read
    ``/projects/:id/protected_branches``. Available to any project
    member with ``read_api``.
  * **SCM-002** reads ``approvals_before_merge`` from
    ``/projects/:id``. Available at read tier.
  * **SCM-006** reads ``push_rules.reject_unsigned_commits`` from
    ``/projects/:id/push_rule``. The push-rules endpoint is a
    GitLab Premium feature and additionally requires Maintainer
    access to the project to read; lower-privilege tokens get a
    silent pass because the rule treats endpoint absence the same
    as "feature disabled".
  * **SCM-008** reads
    ``only_allow_merge_if_pipeline_succeeds`` from
    ``/projects/:id``. Available at read tier.
  * **SCM-017** probes ``/projects/:id/repository/files/<path>`` for
    the three CODEOWNERS locations (``CODEOWNERS``,
    ``.gitlab/CODEOWNERS``, ``docs/CODEOWNERS``). Available at
    read tier.

Self-hosted GitLab: ``--scm-platform gitlab`` accepts a custom
host via the fetcher's ``host=`` constructor argument. Self-hosted
tokens use the same scope name.

## Rule coverage

| Check | Title | Severity |
|-------|-------|----------|
| [SCM-001](scm_github.md#scm-001) | Default branch has no protection rule | HIGH |
| [SCM-002](scm_github.md#scm-002) | Default branch protection does not require pull request reviews | HIGH |
| [SCM-006](scm_github.md#scm-006) | Default branch protection does not require signed commits | MEDIUM |
| [SCM-007](scm_github.md#scm-007) | Default branch protection allows force-pushes | HIGH |
| [SCM-008](scm_github.md#scm-008) | Default branch protection does not require status checks | MEDIUM |
| [SCM-009](scm_github.md#scm-009) | Default branch protection allows branch deletion | HIGH |
| [SCM-017](scm_github.md#scm-017) | Repository has no CODEOWNERS file | MEDIUM |
