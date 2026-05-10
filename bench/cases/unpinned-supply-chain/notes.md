# Unpinned supply chain

The most common CI/CD attack pattern: third-party actions
referenced by tag rather than commit SHA, paired with a
container base image referenced by tag rather than digest. Both
sides float to whatever the upstream maintainer currently serves.

## Real-world incident

**tj-actions/changed-files compromise (CVE-2025-30066, March
2025).** The maintainer-account compromise force-moved the
``@v45`` tag to a commit that exfiltrated CI secrets to a
Memdump-style endpoint. ~23,000 tag-pinned consumers ran the
malicious code on their next workflow run; SHA-pinned consumers
were unaffected unless they happened to be pinned to one of the
two malicious commits.

## What the case demonstrates

  * GHA-001 catches the workflow-side ``@v45`` pin.
  * DF-001 catches the Dockerfile-side ``python:3.12`` tag pin.
  * DF-002 catches the implicit root user — separate concern but
    representative of the "vulnerable composition" the case
    exists to illustrate.
  * GHA-004 catches the missing top-level ``permissions:`` block
    that compounds GHA-001 — even when an unpinned action is
    safe, the GITHUB_TOKEN has the broadest available scope by
    default.

## Fix

Pin every ``uses:`` reference to a 40-char commit SHA; pin the
Dockerfile ``FROM`` to a digest (``FROM python:3.12@sha256:<hex>``);
add ``USER 1001`` to the Dockerfile; declare ``permissions:`` at
the workflow top level (the rule output's ``recommendation`` field
spells out each).
