"""Shared regexes and constants for JF rules.

Jenkins rules take a single ``Jenkinsfile`` object (carrying ``.path``,
``.text``, ``.library_refs``, ``.stages``) rather than the ``(path,
doc)`` pair the YAML providers use — Groovy's not parsable as a dict
so the orchestrator hands the whole parsed blob to each rule.
"""
from __future__ import annotations

import re

# ── Groovy comment stripping ──────────────────────────────────────────
# YAML providers benefit from yaml.safe_load stripping comments before
# token matching.  Jenkins checks work on raw Groovy text, so a comment
# like ``// TODO: add cosign`` would false-positive the signing check.
# This regex-based stripper handles single-line (``//``) and multi-line
# (``/* … */``) comments while leaving string literals untouched.

_GROOVY_TOKEN_RE = re.compile(
    r'""".*?"""'           # triple-double-quoted string
    r"|'''.*?'''"          # triple-single-quoted string
    r'|"(?:[^"\\]|\\.)*"'  # double-quoted string
    r"|'(?:[^'\\]|\\.)*'"  # single-quoted string
    r"|/\*.*?\*/"          # block comment
    r"|//[^\n]*",          # line comment
    re.DOTALL,
)


def strip_groovy_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments, preserving string literals.

    Returns the text with comment bodies replaced by whitespace so
    line numbers stay stable for downstream regex matches.
    """
    def _replace(m: re.Match) -> str:
        s = m.group()
        if s.startswith(("'", '"')):
            return s  # keep string literals
        # Replace comment with spaces (preserve newlines for line counts)
        return re.sub(r"[^\n]", " ", s)
    return _GROOVY_TOKEN_RE.sub(_replace, text)

PINNED_REF_RE = re.compile(r"^(?:v?\d+(?:\.\d+){0,2}|[0-9a-f]{40})$")
FLOATING_REFS = frozenset({"main", "master", "develop", "head", "trunk", "latest"})

UNTRUSTED_ENV_RE = re.compile(
    r"\$\{?\s*(?:env\.)?"
    r"(?:BRANCH_NAME|GIT_BRANCH|TAG_NAME"
    r"|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR(?:_DISPLAY_NAME)?"
    r"|CHANGE_URL|CHANGE_TARGET"
    r"|GIT_AUTHOR_NAME|GIT_AUTHOR_EMAIL"
    r"|GIT_COMMITTER_NAME|GIT_COMMITTER_EMAIL)"
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
#: ``withAWS(credentials: 'id')`` — the AWS Steps plugin with long-lived
#: credentials.  ``withAWS(role: '…')`` is the safe IAM-role pattern and
#: is NOT matched.
WITH_AWS_CREDS_RE = re.compile(
    r"\bwithAWS\s*\(\s*credentials\s*:\s*['\"]",
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

DEPLOY_RE = re.compile(r"(?i)\b(deploy|release|publish|promote)\b")
