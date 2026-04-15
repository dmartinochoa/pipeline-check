"""Shared regex patterns and constants used by multiple check providers.

Kept in one place so AWS (live boto3) and Terraform (plan JSON) checks stay
in sync — any update to a credential detector or managed-image version
automatically applies to both.
"""
from __future__ import annotations

import re

# Environment variable names that suggest a secret is stored in plaintext.
SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH|AUTHORIZATION)",
    re.IGNORECASE,
)

# Credential patterns detectable in the value itself — flags even when the
# variable name is innocuous (e.g. CI_FLAG=AKIA...).
SECRET_VALUE_RE = re.compile(
    r"^(?:"
    r"AKIA[0-9A-Z]{16}|"                          # AWS access key
    r"ASIA[0-9A-Z]{16}|"                          # AWS temporary access key
    r"gh[pousr]_[A-Za-z0-9]{36,}|"                # GitHub PAT / OAuth
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"              # Slack tokens
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"  # JWT
    r")$"
)

# AWS CodeBuild standard managed image — aws/codebuild/standard:X.0.
MANAGED_IMAGE_RE = re.compile(r"aws/codebuild/standard:(\d+)\.\d+")

# Bump when AWS releases a new standard image major version.
LATEST_STANDARD_VERSION = 7
