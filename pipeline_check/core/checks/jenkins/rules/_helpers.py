"""Shared regexes and constants for JF rules.

Jenkins rules take a single ``Jenkinsfile`` object (carrying ``.path``,
``.text``, ``.library_refs``, ``.stages``) rather than the ``(path,
doc)`` pair the YAML providers use — Groovy's not parsable as a dict
so the orchestrator hands the whole parsed blob to each rule.
"""
from __future__ import annotations

import re

PINNED_REF_RE = re.compile(r"^(?:v?\d+(?:\.\d+){0,2}|[0-9a-f]{40})$")
FLOATING_REFS = frozenset({"main", "master", "develop", "head", "trunk", "latest"})

UNTRUSTED_ENV_RE = re.compile(
    r"\$\{?\s*(?:env\.)?"
    r"(?:BRANCH_NAME|GIT_BRANCH|TAG_NAME"
    r"|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR(?:_DISPLAY_NAME)?)"
    r"\s*\}?"
)

SHELL_STEP_RE = re.compile(
    r"(?:sh|bat|powershell|pwsh)\s*\(?\s*"
    r"(?:\"\"\"(?P<triple_d>.*?)\"\"\""
    r"|'''(?P<triple_s>.*?)'''"
    r"|\"(?P<dq>(?:[^\"\\]|\\.)*)\""
    r"|'(?P<sq>(?:[^'\\]|\\.)*)')",
    re.DOTALL,
)

AWS_KEY_BINDING_RE = re.compile(
    r"(?:string|usernamePassword|file)?\s*\(?\s*credentialsId\s*:\s*['\"][^'\"]*aws[^'\"]*['\"]",
    re.IGNORECASE,
)
AWS_KEY_VAR_RE = re.compile(
    r"(?:accessKeyVariable|secretKeyVariable|aws_access_key_id|aws_secret_access_key)",
    re.IGNORECASE,
)

DOCKER_IMAGE_RE = re.compile(
    r"docker\s*\{\s*[^}]*?\bimage\s+['\"]([^'\"]+)['\"]",
    re.DOTALL,
)
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
VERSION_TAG_RE = re.compile(r":[^:]*\d[^:]*$")

ENV_AWS_KEY_RE = re.compile(
    r"(?:^|[\s{])(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

BUILD_DISCARDER_RE = re.compile(r"\b(?:buildDiscarder|logRotator)\s*\(")

LOAD_STEP_RE = re.compile(r"\bload\s+['\"]([^'\"]+\.groovy)['\"]")

COPY_ARTIFACTS_RE = re.compile(r"\b(?:copyArtifacts|CopyArtifact)\b")
VERIFY_RE = re.compile(
    r"\b(?:cosign\s+verify|sha256sum\s+(?:--check|-c)|gpg\s+--verify)\b"
)

DEPLOY_RE = re.compile(r"(?i)(deploy|release|publish|promote)")
