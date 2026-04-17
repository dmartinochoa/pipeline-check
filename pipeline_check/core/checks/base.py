import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml as _yaml

from ..standards.base import ControlRef
from .blob import _BLOB_CACHE, blob_lower, clear_blob_cache, walk_strings
from .tokens import (
    PROVENANCE_TOKENS,
    SBOM_DIRECT_TOKENS,
    SIGN_TOKENS,
    VULN_SCAN_TOKENS,
    _ARTIFACT_TOKENS,
    has_provenance,
    has_sbom,
    has_signing,
    has_vuln_scanning,
    produces_artifacts,
)

# Re-exports — rule files have imported ``walk_strings`` / ``blob_lower`` /
# ``has_signing`` / ``SIGN_TOKENS`` / etc. from this module for a long time.
# The canonical homes are now ``blob.py`` and ``tokens.py`` but we keep the
# old names resolvable here so existing imports don't need to churn.
__all__ = [
    "safe_load_yaml",
    "Severity",
    "severity_rank",
    "Confidence",
    "confidence_rank",
    "Finding",
    "BaseCheck",
    # re-exported from blob
    "walk_strings",
    "blob_lower",
    "clear_blob_cache",
    # re-exported from tokens
    "SIGN_TOKENS",
    "SBOM_DIRECT_TOKENS",
    "PROVENANCE_TOKENS",
    "VULN_SCAN_TOKENS",
    "produces_artifacts",
    "has_signing",
    "has_provenance",
    "has_sbom",
    "has_vuln_scanning",
    # cross-provider script-safety patterns
    "CURL_PIPE_RE",
    "DOCKER_INSECURE_RE",
    "PKG_INSECURE_RE",
    "PKG_NO_LOCKFILE_RE",
    "DEP_UPDATE_RE",
    "has_dep_update",
    "TLS_BYPASS_RE",
    "is_quoted_assignment",
]

# Use the C-accelerated YAML loader when available (libyaml bindings).
# CSafeLoader is functionally identical to SafeLoader but ~30-50x faster,
# which matters when scanning 100+ workflow files in a monorepo.
try:
    _YAML_LOADER = _yaml.CSafeLoader  # type: ignore[attr-defined]
except AttributeError:
    _YAML_LOADER = _yaml.SafeLoader  # type: ignore[assignment]


def safe_load_yaml(text: str) -> Any:
    """Parse YAML using the fastest available safe loader."""
    return _yaml.load(text, Loader=_YAML_LOADER)


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


class Confidence(str, Enum):
    """How strongly a finding is supported by the check's evidence.

    Orthogonal to :class:`Severity`. Severity answers "how bad is this
    if true"; confidence answers "how likely is this to be true at
    all". A CRITICAL-severity regex-blob match can legitimately be
    LOW-confidence — the pattern is strong-sounding but fires on any
    workflow that mentions the token, including docs/examples.

    Consumers filter via ``--min-confidence`` to trade recall for
    precision in CI gates.
    """
    HIGH = "HIGH"       # unambiguous structural evidence
    MEDIUM = "MEDIUM"   # heuristic with known but rare FP modes
    LOW = "LOW"         # blob/text match; meaningful FP rate expected


_CONFIDENCE_RANK: dict["Confidence", int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


def confidence_rank(c: "Confidence") -> int:
    return _CONFIDENCE_RANK[c]


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
    #: CWE identifiers (e.g. ``["CWE-78"]``). Populated by the
    #: workflow-provider orchestrators from the rule's ``cwe`` field.
    cwe: list[str] = field(default_factory=list)
    #: How strongly the check's evidence supports this finding. Rules
    #: that leave this at the default (HIGH) are asserting their match
    #: is structural/unambiguous. Heuristic rules — blob-search pattern
    #: matches, context-dependent warnings — should return MEDIUM or
    #: LOW. The provider orchestrators apply bulk defaults from a
    #: curated list in ``checks/_confidence.py`` so rule authors don't
    #: need to reason about every case.
    confidence: Confidence = Confidence.HIGH
    #: Whether the rule explicitly locked ``confidence`` to the value
    #: above. When False (the default), the Scanner post-processes the
    #: finding by consulting ``checks/_confidence.py`` and may demote
    #: HIGH to MEDIUM/LOW for heuristic rules. When True, the Scanner
    #: leaves the confidence untouched — for rules that need per-
    #: finding control (e.g. CB-005 emitting HIGH for "two+ versions
    #: behind" even though the rule's blanket default is MEDIUM).
    confidence_locked: bool = False

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "resource": self.resource,
            "description": self.description,
            "recommendation": self.recommendation,
            "passed": self.passed,
            "controls": [c.to_dict() for c in self.controls],
            "cwe": self.cwe,
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
        # NB: clearing per-instance guards against id() reuse — a doc
        # that was GC'd between test fixtures can have its id reassigned
        # to a fresh doc, and blob_lower would otherwise return the
        # stale cached blob. The protection outweighs the lost cross-
        # rule sharing within a single scan, so keep the clear.
        clear_blob_cache()

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""


import re as _re

# ── Cross-provider script-safety regexes ──────────────────────────
# Used by the curl-pipe, docker-privileged, and package-insecure
# checks across all five workflow providers.

#: ``curl … | bash`` or ``wget … | sh`` — remote code execution via
#: pipe to interpreter. Covers bash, sh, python, perl, ruby, PowerShell,
#: and download-then-execute variants.
CURL_PIPE_RE = _re.compile(
    r"(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"           # curl | sudo bash
    r"|(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:python[23]?|perl|ruby)\b"  # curl | python3
    r"|(?:ba)?sh\s+(?:-c\s+)?[\"']\$\((?:curl|wget)\b"             # bash -c "$(curl ...)"
    r"|python[23]?\s+-c\s+[\"'].*(?:urllib|requests)\.get\("        # python -c "requests.get(..."
    r"|(?:curl|wget)\s+[^;&]*>\s*\S+\.sh\s*[;&]+\s*(?:ba)?sh\s"    # curl > x.sh && bash x
    r"|irm\s+[^|]*\|\s*iex"                                        # PowerShell: irm | iex
    r"|Invoke-(?:WebRequest|RestMethod)\s+[^|]*\|\s*iex",           # PowerShell long form
)

#: ``docker run --privileged`` or ``-v /…:/…`` — container escape via
#: host mount, privileged mode, namespace sharing, or socket mount.
DOCKER_INSECURE_RE = _re.compile(
    r"docker\s+run\s[^;&]*(?:--privileged|--cap-add|--net[= ]host"
    r"|--pid[= ]host|--userns[= ]host"                              # namespace sharing
    r"|-v\s+/var/run/docker\.sock:/var/run/docker\.sock"            # socket mount
    r"|-v\s+/:/)"                                                   # root mount
    r"|docker\s+compose\s[^;&]*--privileged",                       # compose
)

#: ``pip install --index-url http://`` or ``npm install --registry=http://``
#: — package install from insecure (non-TLS) registry or with trust overrides.
#: Covers pip, npm, yarn, gem, nuget, and cargo.
PKG_INSECURE_RE = _re.compile(
    r"(?:pip3?\s+install)"                                           # pip / pip3
    r"[^;&]*(?:--index-url\s+http[^s]|-i\s+http[^s]"               # -i short form
    r"|--extra-index-url\s+http[^s]"                                 # extra index
    r"|--trusted-host|--no-verify)"
    r"|(?:npm\s+install|yarn\s+add)"
    r"[^;&]*(?:--registry[= ]http[^s]|--no-verify)"
    r"|gem\s+(?:install|sources\s+--add)\s[^;&]*(?:--source\s+http[^s]|http[^s])"  # gem
    r"|nuget\s+(?:install|restore)\s[^;&]*-Source\s+http[^s]"       # nuget
    r"|cargo\s+install\s[^;&]*--index\s+http[^s]",                  # cargo
)

#: Package install without lockfile enforcement — supply-chain risk
#: because the resolver pulls whatever version is currently latest.
PKG_NO_LOCKFILE_RE = _re.compile(
    # npm install (should be npm ci); exempt -g/--global (different concern)
    r"\bnpm\s+install\b(?![^\n]*(?:--frozen|--ci|-g\b|--global\b))"
    # pip install <bare-package> without version pin or lockfile flag.
    # Exempt: -r, --require-hashes, -e, ==version, >=version, ~=, .[extras]
    r"|\bpip3?\s+install\s+(?!-)[a-z][A-Za-z0-9_\-\.]*(?:\s|$)"
    r"(?![^\n]*(?:-r\s|--require-hashes|--requirement))"
    # yarn install without --frozen-lockfile / --immutable
    r"|\byarn\s+install\b(?![^\n]*(?:--frozen-lockfile|--immutable))"
    # bundle install without --frozen / --deployment
    r"|\bbundle\s+install\b(?![^\n]*(?:--frozen|--deployment))"
    # cargo install (always risky in CI without lockfile)
    r"|\bcargo\s+install\s"
    # go install without @vN.N version pin
    r"|\bgo\s+install\s+(?!.*@v\d+\.\d+)\S+(?:\s|$)"
    # poetry install without --no-update
    r"|\bpoetry\s+install\b(?![^\n]*--no-update)",
    _re.MULTILINE,
)


#: Dependency-update commands that bypass lockfile pins.
DEP_UPDATE_RE = _re.compile(
    r"\bpip3?\s+install\s+[^\n]*(?:--upgrade|-U)\b"
    r"|\bnpm\s+update\b"
    r"|\byarn\s+upgrade\b"
    r"|\bbundle\s+update\b"
    r"|\bcargo\s+update\b"
    r"|\bgo\s+get\s+[^\n]*-u\b"
    r"|\bcomposer\s+update\b",
)

#: Tooling upgrades that are safe (pip/setuptools/wheel themselves).
_DEP_UPDATE_TOOL_EXEMPT_RE = _re.compile(
    r"\bpip3?\s+install\s+(?:--upgrade|-U)\s+(?:pip|setuptools|wheel|virtualenv)\b"
)


def has_dep_update(blob: str) -> bool:
    """Return True if *blob* contains a non-exempt dependency-update command."""
    for m in DEP_UPDATE_RE.finditer(blob):
        # Extract the full line so the exemption regex can see the
        # trailing package name (e.g. "pip install --upgrade pip").
        line_start = blob.rfind("\n", 0, m.start()) + 1
        line_end = blob.find("\n", m.end())
        if line_end == -1:
            line_end = len(blob)
        full_line = blob[line_start:line_end]
        if not _DEP_UPDATE_TOOL_EXEMPT_RE.search(full_line):
            return True
    return False


#: TLS / certificate-verification bypass — allows MITM injection.
TLS_BYPASS_RE = _re.compile(
    r"\bnpm\s+config\s+set\s+strict-ssl\s+false\b"
    r"|\byarn\s+config\s+set\s+strict-ssl\s+false\b"
    r"|\bpip3?\s+config\s+set\s+global\.trusted-host\b"
    r"|\bgit\s+config\s+[^\n]*http\.sslverify\s+false\b"
    r"|\bgit_ssl_no_verify\s*=\s*(?:true|1)\b"
    r"|\bnode_tls_reject_unauthorized\s*=\s*['\"]?0['\"]?"
    r"|\bpythonhttpsverify\s*=\s*['\"]?0['\"]?"
    r"|\bcurl\b[^\n]*(?:\s-k\b|\s--insecure\b)"
    r"|\bwget\s+[^\n]*--no-check-certificate\b"
    r"|\bgoinsecure\s*=",
    _re.MULTILINE,
)


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

    **Not** safe when the RHS contains a command substitution like
    ``$( … )`` wrapping untrusted input — the substitution executes
    the content even inside double quotes.
    """
    if not _QUOTED_ASSIGNMENT_RE.match(line):
        return False
    # Extract the RHS after the first '=' and strip the surrounding quotes.
    rhs = line.split("=", 1)[1].strip().strip('"')
    # If the RHS contains $(...) that itself embeds an untrusted
    # interpolation (${{ ... }}, ${VAR}, or bare $VAR), it is NOT safe.
    if _re.search(r"\$\(.*(?:\$\{\{|\$\{?\w|\$\()", rhs):
        return False
    return True
