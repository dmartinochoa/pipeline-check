"""Shared regexes and constants for CC rules."""
from __future__ import annotations

import re

from ..._primitives.deploy_names import DEPLOY_RE as DEPLOY_RE

# Orb pinning — semver or SHA is considered pinned.
# Floating: ``circleci/node@volatile``, ``circleci/node@1``.
# Pinned: ``circleci/node@5.1.0``, ``circleci/node@5.1.0-rc.1``.
PINNED_ORB_RE = re.compile(r"@v?\d+\.\d+\.\d+")
VOLATILE_ORB_RE = re.compile(r"@volatile\b", re.IGNORECASE)

# Docker image digest.
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

# CircleCI attacker-controllable environment variables.
UNTRUSTED_ENV_RE = re.compile(
    r"\$\{?\s*(?:"
    r"CIRCLE_BRANCH|CIRCLE_TAG|CIRCLE_PR_NUMBER"
    r"|CIRCLE_PR_REPONAME|CIRCLE_PR_USERNAME"
    r"|CIRCLE_USERNAME|CIRCLE_PULL_REQUEST"
    r")\s*\}?"
)

# AWS long-lived key env vars (matches variable *names*, not the key
# literal — CircleCI rules look for the presence of these env-var names
# in configs, which is a distinct shape from the ``AKIA…`` literal
# matched by the shared ``secret_shapes.AWS_KEY_RE``).
AWS_KEY_RE = re.compile(
    r"\bAWS_ACCESS_KEY_ID\b|\bAWS_SECRET_ACCESS_KEY\b",
)

# SSH key step without fingerprint restriction.
SSH_NO_FINGERPRINT_RE = re.compile(
    r"add_ssh_keys(?!\s*:\s*\n\s*fingerprints)",
    re.DOTALL,
)

# Cache-key taint: PR-/branch-controlled env vars referenced in
# ``save_cache`` / ``restore_cache`` key fields. A PR can plant a
# poisoned entry under a key derived from ``CIRCLE_BRANCH`` /
# ``CIRCLE_PR_*`` that a later default-branch run restores.
CACHE_TAINT_RE = re.compile(
    r"\{\{\s*\.(?:Branch|Revision)\s*\}\}"
    r"|\{\{\s*\.Environment\.(?:CIRCLE_BRANCH|CIRCLE_TAG|CIRCLE_PR_[A-Z_]+|CIRCLE_PULL_REQUEST)\s*\}\}"
    r"|\$\{?(?:CIRCLE_BRANCH|CIRCLE_TAG|CIRCLE_PR_[A-Z_]+|CIRCLE_PULL_REQUEST)\}?",
)
