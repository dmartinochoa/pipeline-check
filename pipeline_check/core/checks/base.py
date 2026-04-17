import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import yaml as _yaml

from ..standards.base import ControlRef

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
        clear_blob_cache()

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""


def walk_strings(node: Any):
    """Yield every string scalar under a dict/list tree (iterative).

    Uses an explicit stack instead of recursion to reduce function-call
    overhead — a single large workflow can have hundreds of nested
    dict/list nodes, each of which would be a separate generator frame
    in the recursive version.
    """
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


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

# Provenance tokens — narrower than SIGN_TOKENS. SLSA Build L3 requires
# an in-toto attestation produced by a hardened builder, not just a
# signed artifact. Anything here provably produces a provenance
# attestation; ``cosign sign`` alone does NOT (it signs the artifact
# but doesn't emit an in-toto statement describing how it was built).
PROVENANCE_TOKENS = (
    "slsa-github-generator",        # GHA — SLSA Level 3 builder
    "slsa-framework/slsa-",          # SLSA GitHub org actions
    "actions/attest-build-provenance",  # GHA — native build-provenance action
    "actions/attest@",               # GHA — generic attest action
    "cosign attest",                 # sigstore attestation (distinct from `cosign sign`)
    "witness run",                   # testifysec/witness attestor
    "in-toto-attestation",           # in-toto library/CLI
    "intoto.jsonl",                  # standard provenance filename
    "provenance.intoto",             # common provenance output name
)


# Tokens that indicate a workflow produces deployable artifacts.
# Used by the signing/SBOM/vuln-scan checks to suppress false positives
# on lint/test-only workflows that don't produce anything to sign or scan.
_ARTIFACT_TOKENS = (
    "docker push", "docker build",
    "upload-artifact", "actions/upload-artifact",
    "archiveartifacts",                         # Jenkins
    "store_artifacts", "persist_to_workspace",  # CircleCI
    "publish", "deploy", "release",
    "docker/build-push-action",
    "docker/metadata-action",
    "aws s3 cp", "aws s3 sync",
    "kubectl apply", "helm upgrade", "helm install",
    "terraform apply",
    "gcloud app deploy", "gcloud run deploy",
    "twine upload", "cargo publish", "gem push",
    "npm publish", "yarn publish",
)


def produces_artifacts(doc: Any) -> bool:
    """Return True when the workflow appears to produce deployable artifacts.

    Heuristic: if no artifact-production token appears anywhere in the
    workflow's string content, the workflow is likely lint/test-only and
    the signing/SBOM/vulnerability-scanning checks should not fire.
    """
    blob = blob_lower(doc)
    return any(tok in blob for tok in _ARTIFACT_TOKENS)


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


# The cache is cleared in ``BaseCheck.__init__`` and in
# ``Scanner._scan_provider`` so entries from a previous scan
# (especially in long-lived Lambda containers) can't pin memory
# or — worse — collide with a newly-allocated doc that reused the
# freed ``id()``.
_BLOB_CACHE: dict[int, str] = {}


def clear_blob_cache() -> None:
    _BLOB_CACHE.clear()


def has_signing(doc: Any) -> bool:
    blob = blob_lower(doc)
    return any(tok in blob for tok in SIGN_TOKENS)


def has_provenance(doc: Any) -> bool:
    """Return True when the workflow emits an in-toto/SLSA provenance attestation.

    Distinct from :func:`has_signing` — a workflow that only runs
    ``cosign sign`` signs the artifact but doesn't produce a
    provenance statement describing *how* the artifact was built.
    SLSA Build Level 3 requires the latter.
    """
    blob = blob_lower(doc)
    return any(tok in blob for tok in PROVENANCE_TOKENS)


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


#: Vulnerability scanning tool tokens — same detection pattern as
#: ``has_signing`` / ``has_sbom``.
VULN_SCAN_TOKENS = (
    "trivy ", "grype ", "snyk ", "npm audit", "yarn audit",
    "safety check", "pip-audit", "osv-scanner", "govulncheck",
    "cargo audit", "bundler-audit", "bundle audit",
    "docker scout", "codeql-action", "github/codeql-action",
    "semgrep ", "bandit ", "checkov ", "tfsec ",
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
