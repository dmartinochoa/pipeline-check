# Unprotected source ships mutable runtime image

The textbook XPC-008 composition: an SCM repo with no branch
protection rule on the default branch AND a Dockerfile that
pulls its base image by floating tag. Each leg is bad on its
own; together the attacker primitive collapses to "land a
tampered ``FROM`` change with no review gate, AND every
subsequent build inherits the new upstream bytes."

This case demonstrates the SCM provider running in the bench
surface for the first time. Production runs of the SCM provider
hit the GitHub REST API with ``--scm-platform github
--scm-repo owner/name`` and a token; bench mode reads JSON
fixtures from ``scm/`` via ``DiskSCMFetcher`` so the case stays
hermetic — no network, no token, no rate-limit risk during
``pytest`` or ``python bench/run.py``.

## Fixture layout

  * ``scm_config.json`` declares the synthetic repo identity
    the provider uses to build its endpoint paths
    (``{"owner": "octocat", "name": "demo-app"}``).
  * ``scm/repos_octocat_demo-app.json`` is the repo-meta API
    response (with ``default_branch: main`` and ``size: 1024``,
    so the empty-repo guard doesn't kick in).
  * ``scm/`` deliberately omits ``repos_octocat_demo-app_branches_main_protection.json``.
    The fetcher returns ``None`` for the missing file; the SCM
    provider treats that as "no protection rule" and SCM-001
    fires.
  * ``Dockerfile`` pulls ``FROM ubuntu:22.04`` — a tag, not a
    digest — which trips DF-001.

## What the case demonstrates

  * SCM-001 fires on the missing-protection-rule fixture.
  * DF-001 fires on the floating-tag Dockerfile.
  * XPC-008 fires on the (SCM-001, DF-001) cross-provider pair
    via the chain engine that ``bench/run.py`` evaluates over
    the union of all per-provider findings.

This is the bench's first SCM-touching case and the first
demonstration that the SCM provider participates in the chain
correlation surface, not just the rule pack.

## Fix

Add a branch protection rule on the default branch (require
PR reviews, deny force-pushes, deny deletions) AND pin the
Dockerfile ``FROM`` to a digest. Either alone narrows the
chain; both close it. See ``--explain SCM-001`` and
``--explain DF-001`` for the per-leg remediation.
