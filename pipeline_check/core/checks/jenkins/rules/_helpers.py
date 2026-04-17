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

# ── JF-024: input step submitter guard ────────────────────────────────
#: Matches an ``input`` step call (both short and block forms). Used to
#: extract the enclosing argument region so JF-024 can check for a
#: ``submitter:`` field. A bare presence check lives in JF-005.
INPUT_STEP_RE = re.compile(r"\binput\b", re.MULTILINE)
#: Detects a ``submitter`` binding anywhere in the argument span.
#: Groovy allows two syntaxes:
#:   ``submitter: 'releasers,sre'``   (map-style named arg)
#:   ``submitter 'releasers,sre'``    (DSL block-step call)
#: Both forms pin a non-empty comma-separated list of users/roles.
SUBMITTER_FIELD_RE = re.compile(
    r"\bsubmitter\s*(?::|\s)\s*['\"]([^'\"]+)['\"]"
)

# ── JF-025: Kubernetes agent pod template ─────────────────────────────
#: Matches the ``kubernetes { ... }`` block inside an ``agent { ... }``
#: declaration. Jenkins supports both ``yaml '''...'''`` and ``yamlFile
#: 'pod.yaml'`` forms.
K8S_AGENT_RE = re.compile(r"\bkubernetes\s*\{", re.MULTILINE)
#: Privileged security-context in an embedded pod YAML. Matches
#: ``privileged: true`` on its own line (YAML key/value), NOT Groovy
#: variable assignments like ``privileged = true``.
K8S_PRIVILEGED_RE = re.compile(
    r"(?m)^\s*privileged\s*:\s*true\b"
)
#: ``hostPath:`` volume in the embedded pod YAML — mounts a host
#: filesystem path, allowing container escape.
K8S_HOSTPATH_RE = re.compile(r"(?m)^\s*hostPath\s*:")
#: ``hostNetwork: true`` or ``hostPID: true`` — share host
#: namespaces.
K8S_HOSTNS_RE = re.compile(
    r"(?m)^\s*host(?:Network|PID|IPC)\s*:\s*true\b"
)

# ── JF-026: build job trigger without result check ────────────────────
#: Matches ``build job: '<name>'`` — the Pipeline-plugin step that
#: triggers a downstream job.
BUILD_JOB_RE = re.compile(
    r"\bbuild\s+(?:job\s*:|\(\s*job\s*:)\s*['\"]([^'\"]+)['\"]"
)
#: Captures a ``wait:`` argument from a ``build job:`` invocation.
#: Groovy allows either positional or map-style args.
BUILD_WAIT_FALSE_RE = re.compile(
    r"\bbuild\s+\(?[^)]*\bwait\s*:\s*false\b",
    re.DOTALL,
)
#: Captures a ``propagate:`` argument from a ``build job:`` invocation.
#: ``propagate: false`` is equally dangerous because downstream failures
#: don't abort the upstream job.
BUILD_PROPAGATE_FALSE_RE = re.compile(
    r"\bbuild\s+\(?[^)]*\bpropagate\s*:\s*false\b",
    re.DOTALL,
)

# ── JF-027: archiveArtifacts fingerprint ──────────────────────────────
#: Matches the ``archiveArtifacts`` step (positional or map-style).
ARCHIVE_ARTIFACTS_RE = re.compile(
    r"\barchiveArtifacts\b"
)
#: ``fingerprint: true`` — instructs Jenkins to record the artifact
#: digest so consumers of ``copyArtifacts`` can verify provenance.
FINGERPRINT_TRUE_RE = re.compile(
    r"\bfingerprint\s*:\s*true\b"
)
