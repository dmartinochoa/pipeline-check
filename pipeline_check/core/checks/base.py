import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

import yaml as _yaml

from ..standards.base import ControlRef
from .blob import blob_lower, clear_blob_cache, walk_strings
from .tokens import _ARTIFACT_TOKENS as _ARTIFACT_TOKENS
from .tokens import (
    PROVENANCE_TOKENS,
    SBOM_DIRECT_TOKENS,
    SIGN_TOKENS,
    VULN_SCAN_TOKENS,
    has_provenance,
    has_sbom,
    has_signing,
    has_vuln_scanning,
    produces_artifacts,
)

# Re-exports, rule files have imported ``walk_strings`` / ``blob_lower`` /
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
    "Location",
    "ResourceAnchor",
    "ControlRef",
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
    "DOCKER_INSECURE_RE",
    "PKG_INSECURE_RE",
    "PKG_NO_LOCKFILE_RE",
    "DEP_UPDATE_RE",
    "has_dep_update",
    "is_quoted_assignment",
    "NO_ARTIFACT_DESC",
]

#: Standard ``description`` for an artifact-pack rule (signing, SBOM,
#: vuln-scanning, SLSA provenance) that short-circuits to passed=True
#: because the pipeline doesn't produce build artifacts in the first
#: place. Imported by every rule in the GHA-006/007 family across the
#: provider pack so the wording stays consistent and a future reword
#: lands in one place.
NO_ARTIFACT_DESC: str = "No artifact production detected, check not applicable."

# Use the C-accelerated YAML loader when available (libyaml bindings).
# CSafeLoader is functionally identical to SafeLoader but ~30-50x faster,
# which matters when scanning 100+ workflow files in a monorepo. The
# union annotation declares both arms so types-PyYAML doesn't reject
# the fallback as a narrowing assignment from CSafeLoader.
_YAML_LOADER: type[_yaml.CSafeLoader] | type[_yaml.SafeLoader]
try:
    _YAML_LOADER = _yaml.CSafeLoader
except AttributeError:
    _YAML_LOADER = _yaml.SafeLoader


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
    LOW-confidence, the pattern is strong-sounding but fires on any
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


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding lands inside a source file.

    Lines and columns are 1-based to match SARIF, every common editor,
    and every other security tool's output. ``end_line`` defaults to
    the same value as ``start_line`` for single-line findings; ranges
    that span multiple lines set both. ``doc_index`` distinguishes
    documents inside a multi-doc YAML stream (Kubernetes / Tekton /
    Argo), index 0 means the first ``---``-separated body.

    A finding can carry zero, one, or many locations. Zero locations
    means line precision wasn't available (e.g. AWS live-API scans
    have no source file); reporters fall back to ``Finding.resource``.
    Many locations is the canonical aggregate-rule shape: a single
    ``Finding`` describing N offenders spread across the file, one
    ``Location`` per offender.
    """

    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    doc_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        if self.start_line is not None:
            out["start_line"] = self.start_line
        if self.end_line is not None:
            out["end_line"] = self.end_line
        if self.start_column is not None:
            out["start_column"] = self.start_column
        if self.end_column is not None:
            out["end_column"] = self.end_column
        if self.doc_index is not None:
            out["doc_index"] = self.doc_index
        return out


@dataclass(frozen=True, slots=True)
class ResourceAnchor:
    """A cross-provider reference to an external resource.

    The cross-provider counterpart to :class:`Finding.job_anchors`.
    ``job_anchors`` ties two findings together when they fire on the
    same execution unit (job, step) of the *same* pipeline file. That
    works for within-provider chains but doesn't fit cross-provider
    cases where the natural reachability claim is "two findings
    reference the same external resource" — e.g. a GitHub workflow's
    ``role-to-assume`` ARN matching the role IAM-002 flagged as
    wildcard.

    ``kind`` is the resource taxonomy (``iam_role``, ``ecr_repo``,
    ``k8s_sa``, ``lambda_fn``, ``oci_image``, …); ``identity`` is the
    canonical string for that kind. Rules go through
    :mod:`pipeline_check.core.checks._primitives.anchors` to build
    these so both legs of a cross-provider chain agree on a single
    canonical form and intersect mechanically.

    ``(kind, identity)`` is the equality key; chain rules intersect
    by treating the per-leg anchor sets as ``set[(kind, identity)]``
    and looking for non-empty overlap.
    """

    kind: str
    identity: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "identity": self.identity}


@dataclass(slots=True)
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
    #: Real-world incident references the rule is anchored to.
    #: Populated by the workflow-provider orchestrators from the
    #: rule's ``incident_refs`` field. Surfaced in the HTML report
    #: under a "Seen in the wild" footer; empty for rules whose risk
    #: has no public incident on record.
    incident_refs: list[str] = field(default_factory=list)
    #: Proof-of-exploit snippet copied from the rule's
    #: ``exploit_example`` field by the orchestrators. Surfaced in
    #: ``pipeline_check --explain`` and the HTML report under a
    #: "Proof of exploit" section. ``None`` for rules where the bad
    #: pattern is itself the exploit, or where no public exploitation
    #: primitive exists.
    exploit_example: str | None = None
    #: How strongly the check's evidence supports this finding. Rules
    #: that leave this at the default (HIGH) are asserting their match
    #: is structural/unambiguous. Heuristic rules, blob-search pattern
    #: matches, context-dependent warnings, should return MEDIUM or
    #: LOW. The provider orchestrators apply bulk defaults from a
    #: curated list in ``checks/_confidence.py`` so rule authors don't
    #: need to reason about every case.
    confidence: Confidence = Confidence.HIGH
    #: Whether the rule explicitly locked ``confidence`` to the value
    #: above. When False (the default), the Scanner post-processes the
    #: finding by consulting ``checks/_confidence.py`` and may demote
    #: HIGH to MEDIUM/LOW for heuristic rules. When True, the Scanner
    #: leaves the confidence untouched, for rules that need per-
    #: finding control (e.g. CB-005 emitting HIGH for "two+ versions
    #: behind" even though the rule's blanket default is MEDIUM).
    confidence_locked: bool = False
    #: Structured source locations the finding refers to. Optional;
    #: ``[]`` means the rule didn't compute precise lines and reporters
    #: should fall back to ``resource``. Populated by rules that have
    #: line-aware loaders available (workflow YAML providers,
    #: Dockerfile, K8s/Helm/Tekton/Argo). AWS / Terraform / CloudFormation
    #: stay at ``[]`` because their inputs aren't line-anchored source.
    locations: list[Location] = field(default_factory=list)
    #: Job identifiers the finding pertains to within ``resource``.
    #: Used by the reachability-aware chain engine to intersect the
    #: jobs an injection source fires in with the jobs an impact rule
    #: (deploy, privilege) fires in: a non-empty intersection means the
    #: two legs of the chain are co-located in the same job and the
    #: chain is reachable, not just co-occurrence in the same file.
    #: ``()`` (the default) means the rule didn't compute per-job
    #: anchors; chain rules treat that as "co-occurrence only".
    job_anchors: tuple[str, ...] = ()
    #: Rendered taint paths the finding evidences (e.g.
    #: ``${{ github.event.issue.title }}@extract[0] -> steps.extract.outputs.title -> sink@deploy[2](kubectl)``).
    #: Populated by the TAINT-NNN family; consumed by reachability-
    #: aware chain rules and by ``--explain`` so a reader sees the
    #: full source-to-sink hop chain without re-reading the description.
    path_evidence: tuple[str, ...] = ()
    #: External resources this finding references, in canonical form.
    #: Used by the cross-provider chain engine: when two legs of a
    #: chain anchor on the same ``(kind, identity)``, the chain is
    #: reachable across providers (e.g. a GHA workflow's
    #: ``role-to-assume`` ARN matching the role IAM-002 analyzed).
    #: Empty tuple (the default) means the rule didn't compute any
    #: cross-resource anchor; cross-provider chains then treat the
    #: leg as co-occurrence only. Distinct from ``job_anchors``,
    #: which is within-pipeline-file. Rules go through
    #: ``checks/_primitives/anchors.py`` to build entries so both
    #: legs agree on a canonical form.
    resource_anchors: tuple[ResourceAnchor, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
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
        if self.incident_refs:
            out["incident_refs"] = list(self.incident_refs)
        if self.exploit_example is not None:
            out["exploit_example"] = self.exploit_example
        if self.locations:
            out["locations"] = [loc.to_dict() for loc in self.locations]
        if self.job_anchors:
            out["job_anchors"] = list(self.job_anchors)
        if self.path_evidence:
            out["path_evidence"] = list(self.path_evidence)
        if self.resource_anchors:
            out["resource_anchors"] = [a.to_dict() for a in self.resource_anchors]
        return out


_ContextT = TypeVar("_ContextT")


class BaseCheck(abc.ABC, Generic[_ContextT]):
    """Provider-agnostic base for all check modules.

    Subclasses declare a PROVIDER class attribute so the Scanner can route
    them to the correct pipeline environment, and parameterize the generic
    on whatever context object their provider requires (e.g.
    ``BaseCheck[boto3.Session]`` for AWS, ``BaseCheck[GitHubContext]`` for
    GitHub, ``BaseCheck[JenkinsContext]`` for Jenkins). The generic param
    pins ``self.context`` to the concrete type so subclass methods reading
    it get type-narrowing without needing to re-assert via a local cast.
    """

    #: Pipeline environment this check targets.  Override in subclasses.
    PROVIDER: str = ""

    def __init__(self, context: _ContextT, target: str | None = None) -> None:
        self.context: _ContextT = context
        #: Optional resource name to scope the scan to (e.g. a pipeline name).
        self.target = target
        # NB: clearing per-instance guards against id() reuse, a doc
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
# Used by the docker-privileged and package-insecure checks across
# all workflow providers. The curl-pipe and TLS-bypass detectors
# moved to ``_primitives/remote_script_exec.py`` and
# ``_primitives/tls_bypass.py`` respectively. Every provider rule
# now calls those primitives directly; the legacy combined
# ``CURL_PIPE_RE`` / ``TLS_BYPASS_RE`` constants were removed once
# the holdouts (BK-004, BK-008, DR-006, ARGO-008, TKN-008) migrated.

#: ``docker run --privileged`` or ``-v /…:/…``, container escape via
#: host mount, privileged mode, namespace sharing, or socket mount.
DOCKER_INSECURE_RE = _re.compile(
    r"docker\s+run\s[^;&]*(?:--privileged|--cap-add|--net[= ]host"
    r"|--pid[= ]host|--userns[= ]host"                              # namespace sharing
    r"|-v\s+/var/run/docker\.sock:/var/run/docker\.sock"            # socket mount
    r"|-v\s+/:/)"                                                   # root mount
    r"|docker\s+compose\s[^;&]*--privileged",                       # compose
)

#: ``pip install --index-url http://`` or ``npm install --registry=http://``
#:, package install from insecure (non-TLS) registry or with trust overrides.
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

#: Package install without lockfile enforcement, supply-chain risk
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

#: Tooling upgrades that are safe.
#:
#: Two categories:
#:
#:   * Build-system tools, ``pip``, ``setuptools``, ``wheel``,
#:     ``virtualenv``, ``build``. These are used to produce / install
#:     the artifact, not to ship inside it.
#:   * Security-tooling installs, ``pip-audit``, ``cyclonedx-bom``,
#:     ``cyclonedx-py``, ``safety``, ``bandit``, ``semgrep``. These
#:     are CI scanners that lint or attest the artifact; the version
#:     pin churn is irrelevant to the supply chain because their
#:     output never lands in the wheel.
_DEP_UPDATE_TOOL_EXEMPT_RE = _re.compile(
    r"\bpip3?\s+install\s+(?:--upgrade|-U)\s+(?:"
    r"pip|setuptools|wheel|virtualenv|build"
    r"|pip-audit|cyclonedx-bom|cyclonedx-py|safety|bandit|semgrep|ruff|mypy"
    r")\b"
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
    ``$( … )`` wrapping untrusted input, the substitution executes
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
