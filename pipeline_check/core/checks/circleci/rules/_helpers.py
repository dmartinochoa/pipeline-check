"""Shared regexes and constants for CC rules."""
from __future__ import annotations

import re

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

# Deploy-like job/workflow names.
DEPLOY_RE = re.compile(r"(?i)\b(deploy|release|publish|promote)\b")

# AWS long-lived key env vars.
AWS_KEY_RE = re.compile(
    r"\bAWS_ACCESS_KEY_ID\b|\bAWS_SECRET_ACCESS_KEY\b",
)

# SSH key step without fingerprint restriction.
SSH_NO_FINGERPRINT_RE = re.compile(
    r"add_ssh_keys(?!\s*:\s*\n\s*fingerprints)",
    re.DOTALL,
)
