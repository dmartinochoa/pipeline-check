# Pwn request

The canonical "fork PR triggers privileged execution" attack
pattern. ``pull_request_target`` runs with the base repo's
secrets and a write-scope ``GITHUB_TOKEN``; checking out the PR
head into that context executes attacker code with those
privileges.

## Real-world incident

**GitHub Security Lab disclosure (2020):** "Preventing pwn
requests" documented dozens of widely-used Actions workflows
hitting this exact pattern. The fix pattern (split the workflow
into a privileged labeler + an unprivileged builder) became
standard guidance.

**Trail of Bits ``Codecov-style supply chain via pwn requests``
(2021):** showed the primitive against marketplace Actions where
the maintainer never noticed the pattern.

## What the case demonstrates

  * GHA-002 catches the ``pull_request_target`` + PR-head
    checkout combination.
  * GHA-003 catches the script injection via PR title that the
    same workflow ships alongside (interpolating
    ``${{ github.event.pull_request.title }}`` into ``run:``).
  * GHA-019 catches the token persistence to ``$GITHUB_ENV`` —
    the workflow then uploads everything as an artifact, so any
    contributor can fetch the token from the build output.

The composite is what XPC-006 fires on when paired with an SCM
finding (no required reviews on the default branch).

## Fix

Replace ``pull_request_target`` with ``pull_request`` for any
workflow that runs fork-PR code. If write scope is needed (e.g.
to label PRs), split the workflow: a labeler that runs in
``pull_request_target`` context but never checks out PR head, and
a separate ``pull_request``-triggered builder that runs the
fork code with no secrets in scope.
