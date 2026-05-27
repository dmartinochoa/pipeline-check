# SCM posture: Bitbucket Cloud

Scans Bitbucket Cloud repository governance via the REST API. Runs
the seven universal SCM rules shared across all platforms.
GitHub-only rules (SCM-003..005, SCM-010..016, SCM-018..049) pass
silently with a "not applicable on bitbucket" note. Bitbucket
Server is a different surface and not currently in scope.

See the [SCM posture overview](scm.md) for shared concepts and the
[GitHub page](scm_github.md) for the full rule reference.

## Producer workflow

```bash
# Token is ``user:app_password`` or the existing
# ``Basic <b64>`` Authorization value; falls back to
# $BITBUCKET_TOKEN. Repo spec is ``workspace/repo_slug``.
pipeline_check --pipeline scm --scm-platform bitbucket \
    --scm-repo acme/widget

# Offline / CI mode: read JSON responses from disk.
pipeline_check --pipeline scm --scm-platform bitbucket \
    --scm-repo acme/widget \
    --scm-fixture-dir ./scm-fixtures/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

## Token permissions

Pass the credential as ``user:app_password`` via ``--gh-token`` (or
``$BITBUCKET_TOKEN``).

| Tier | App-password permissions | Rules unlocked |
|------|--------------------------|----------------|
| public (no credential) | — | SCM-001, -002, -007, -008, -009, -017 on public repos only |
| read | ``repositories:read`` | full universal-rule coverage on private repos |

## Per-rule behavior

  * **SCM-001 / SCM-007 / SCM-009** read
    ``/repositories/{workspace}/{repo}/branch-restrictions``
    (``push`` / ``force`` / ``delete`` restriction kinds).
    Available at ``repositories:read``.
  * **SCM-002 / SCM-008** read ``require_approvals_to_merge`` and
    ``require_passing_builds_to_merge`` from the same endpoint.
    Available at ``repositories:read``.
  * **SCM-006 has no Bitbucket Cloud equivalent.** Bitbucket
    Cloud has no per-branch signed-commit enforcement (GPG
    signing is a personal-account UI setting, not a protection
    rule). The rule always fires on Bitbucket snapshots; suppress
    per repo with a rationale if the team enforces signing via a
    different mechanism.
  * **SCM-017** probes
    ``/repositories/{workspace}/{repo}/src/<branch>/<path>?format=meta``
    for the three CODEOWNERS locations (``CODEOWNERS``,
    ``.bitbucket/CODEOWNERS``, ``docs/CODEOWNERS``). Available at
    ``repositories:read``.

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
