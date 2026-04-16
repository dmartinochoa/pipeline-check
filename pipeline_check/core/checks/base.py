import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..standards.base import ControlRef


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Ascending order: INFO is least severe, CRITICAL is most severe.
_SEVERITY_RANK: dict["Severity", int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(s: "Severity") -> int:
    return _SEVERITY_RANK[s]


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    description: str
    recommendation: str
    passed: bool
    #: Compliance controls this finding evidences. Populated by the Scanner
    #: from the standards registry after a check runs; checks never set this
    #: directly.
    controls: list[ControlRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "recommendation": self.recommendation,
            "passed": self.passed,
            "controls": [c.to_dict() for c in self.controls],
        }


class BaseCheck(abc.ABC):
    """Provider-agnostic base for all check modules.

    Subclasses declare a PROVIDER class attribute so the Scanner can route
    them to the correct pipeline environment, and accept whatever context
    object their provider requires (e.g. a boto3 Session for AWS, a
    google-auth credential for GCP, a token for GitHub).
    """

    #: Pipeline environment this check targets.  Override in subclasses.
    PROVIDER: str = ""

    def __init__(self, context: Any, target: str | None = None) -> None:
        self.context = context
        #: Optional resource name to scope the scan to (e.g. a pipeline name).
        self.target = target

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""


def walk_strings(node: Any):
    """Recursively yield every string scalar found under a dict/list tree."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_strings(v)


# Case-insensitive substring tokens; a workflow passes the signing check if
# any token appears anywhere in its string content.
SIGN_TOKENS = (
    "cosign", "sigstore", "slsa-github-generator",
    "slsa-framework/slsa-", "notation-sign",
)

# SBOM tokens: direct hits pass on their own. Trivy only passes when combined
# with "sbom" or "cyclonedx" in the same blob.
SBOM_DIRECT_TOKENS = (
    "cyclonedx", "syft", "anchore/sbom-action",
    "spdx-sbom-generator", "microsoft/sbom-tool",
)


def blob_lower(doc: Any) -> str:
    """Concatenate all string values in ``doc`` into one lowercase blob.

    Memoised on object identity so that the multiple callers each
    provider uses (``has_signing``, ``has_sbom``, and — through the
    secrets helper — ``find_secret_values``) share one tree walk per
    workflow. ``id(doc)`` is stable for as long as the document
    object is alive, which is the whole ``run()`` invocation.
    """
    key = id(doc)
    cached = _BLOB_CACHE.get(key)
    if cached is not None:
        return cached
    blob = "\n".join(walk_strings(doc)).lower()
    _BLOB_CACHE[key] = blob
    return blob


# The cache is cleared at the top of every ``BaseCheck.run`` via
# :func:`clear_blob_cache` so entries from a previous scan (especially
# in long-lived Lambda containers) can't pin memory or — worse —
# collide with a newly-allocated doc that reused the freed ``id()``.
_BLOB_CACHE: dict[int, str] = {}


def clear_blob_cache() -> None:
    _BLOB_CACHE.clear()


def has_signing(doc: Any) -> bool:
    blob = blob_lower(doc)
    return any(tok in blob for tok in SIGN_TOKENS)


def has_sbom(doc: Any) -> bool:
    blob = blob_lower(doc)
    if any(tok in blob for tok in SBOM_DIRECT_TOKENS):
        return True
    if "trivy" in blob and ("sbom" in blob or "cyclonedx" in blob):
        return True
    return False


import re as _re

# ── Cross-provider script-safety regexes ──────────────────────────
# Used by the curl-pipe, docker-privileged, and package-insecure
# checks across all five workflow providers.

#: ``curl … | bash`` or ``wget … | sh`` — remote code execution via
#: pipe to interpreter. Covers bash, sh, python, perl, ruby.
CURL_PIPE_RE = _re.compile(
    r"(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh\b"
    r"|(?:curl|wget)\s+[^|]*\|\s*(?:python|perl|ruby)\b",
)

#: ``docker run --privileged`` or ``-v /…:/…`` — container escape via
#: host mount or privileged mode.
DOCKER_INSECURE_RE = _re.compile(
    r"docker\s+run\s[^;&]*(?:--privileged|--cap-add|--net[= ]host"
    r"|-v\s+/[^:\s]*:/)",
)

#: ``pip install --index-url http://`` or ``npm install --registry=http://``
#: — package install from insecure (non-TLS) registry or with trust overrides.
PKG_INSECURE_RE = _re.compile(
    r"(?:pip\s+install|npm\s+install|yarn\s+add|gem\s+install)"
    r"[^;&]*(?:--index-url\s+http[^s]|--registry[= ]http[^s]"
    r"|--trusted-host|--no-verify)",
)

#: Vulnerability scanning tool tokens — same detection pattern as
#: ``has_signing`` / ``has_sbom``.
VULN_SCAN_TOKENS = (
    "trivy ", "grype ", "snyk ", "npm audit", "yarn audit",
    "safety check", "pip-audit", "osv-scanner", "govulncheck",
)


def has_vuln_scanning(doc: Any) -> bool:
    """Return True if the pipeline invokes a known vulnerability scanner."""
    blob = blob_lower(doc)
    return any(tok in blob for tok in VULN_SCAN_TOKENS)


# A shell *assignment* like ``VAR="$UNTRUSTED"`` captures the value
# into a variable; the untrusted content is not executed unless a
# later command inlines the resulting ``$VAR`` unquoted. All four
# workflow-provider script-injection checks skip lines that match
# this pattern so the obvious "safe idiom" doesn't false-positive.
#
# Matches shell-style ``${VAR}``, ADO-style ``$(VAR)``, and
# GitHub-style ``${{ ... }}`` expression interpolations inside the
# quoted string so every provider can share one helper.
_QUOTED_ASSIGNMENT_RE = _re.compile(
    r'\s*\w+="[^"]*'
    r'(?:'
    r'\$\{\{[^}]*\}\}'     # GitHub ${{ ... }}
    r'|\$\{?\w+\}?'        # shell ${VAR} / $VAR
    r'|\$\([^)]+\)'        # ADO $(VAR)
    r')'
    r'[^"]*"\s*$'
)


def is_quoted_assignment(line: str) -> bool:
    """Return True if *line* is a ``VAR="…$X…"`` assignment (a safe idiom).

    Shared between the GitHub, GitLab, Bitbucket, and Azure
    script-injection checks so the "this is just capturing the value,
    not executing it" escape hatch is applied consistently.
    """
    return bool(_QUOTED_ASSIGNMENT_RE.match(line))
