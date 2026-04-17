"""Context-aware suppression helpers.

Reduce false positives on pattern matches that would otherwise fire
inside documentation, example blocks, or fixture values. Kept next to
``_malicious.py`` / ``_patterns.py`` so rule authors have one import
surface for "should I actually flag this?".

Heuristics are deliberately simple and err on the side of not
suppressing: a LOW-confidence finding is better than a silenced true
positive.
"""
from __future__ import annotations

import re

# Key / attribute names that signal the surrounding string is an
# example, not production data. Matched against the *nearest enclosing
# YAML key or HCL attribute name* walking backwards from the match.
_EXAMPLE_KEY_RE = re.compile(
    r"(?i)\b(?:example|examples|sample|samples|demo|"
    r"doc|docs|documentation|fixture|fixtures|test|tests|"
    r"dummy|fake|placeholder|mock|"
    r"readme|changelog)\b"
)

# Inline example markers — deliberately narrow. Must appear attached
# to a comment marker or assignment, NOT in free text. Matching a bare
# word like "example" anywhere in the window would false-suppress on
# ``example.com`` (RFC 2606 reserved domain used by real attackers as
# lure) and on module names like ``aws-examples``. These patterns fire
# only when the word sits in an obvious annotation position.
#
# The comment marker must start a line (with optional leading
# whitespace) so ``//`` inside a URL like ``https://example.com`` does
# not trigger suppression — that false-positive would silence CRITICAL
# findings (reverse shells, exfil channels) any time a workflow
# happened to reference an RFC 2606 example domain.
_EXAMPLE_INLINE_RE = re.compile(
    r"(?im)"
    r"(?:^\s*)"                                                # line start
    r"(?:#|//|--|\*)\s*"                                       # comment marker
    r"(?:this\s+is\s+)?"
    r"(?:an?\s+)?"
    r"(?:example|sample|demo|fake|dummy|placeholder|mock|fixture)\b"
    r"|"
    r"\b(?:placeholder|dummy)\s*[=:]\s*"                       # assignment label
)


def looks_like_example(blob: str, match_start: int, window: int = 200) -> bool:
    """Return True when the match appears to live inside example/doc content.

    Two heuristics, both conservative:

    1. **YAML ancestor chain** — walk all preceding ``^<indent>key:``
       declarations with strictly less indent than the line containing
       *match_start*. If any ancestor's key matches an example marker,
       the match lives inside an example/fixture block.
    2. **Inline comment marker** — a comment line preceding the match
       that labels the block as an example (``# example:``,
       ``// sample``).

    Bare occurrences of "example" in free text (e.g. ``example.com``
    as a lure hostname) do NOT trigger suppression — inline detection
    requires an explicit comment or assignment marker.
    """
    # Line containing the match.
    line_start = blob.rfind("\n", 0, match_start) + 1
    line_end = blob.find("\n", match_start)
    if line_end == -1:
        line_end = len(blob)
    match_line = blob[line_start:line_end]
    match_indent = len(match_line) - len(match_line.lstrip(" "))

    # YAML ancestors: any preceding ``^<indent>key:`` with strictly
    # less indent than the match line. The most recent at each indent
    # level is the effective ancestor (later same-indent keys are
    # siblings).
    keys_by_indent: dict[int, str] = {}
    for m in re.finditer(
        r"(?m)^(?P<ind> *)(?P<name>[A-Za-z_][\w-]*)\s*:",
        blob[:line_start],
    ):
        indent = len(m.group("ind"))
        if indent < match_indent:
            keys_by_indent[indent] = m.group("name")
    for name in keys_by_indent.values():
        if _EXAMPLE_KEY_RE.search(name):
            return True

    # HCL attribute: ``<name> = ...`` — no indentation semantics in
    # HCL so scope the walk to a local window.
    prior = blob[max(0, match_start - window):match_start]
    for m in re.finditer(r"(?m)^\s*([A-Za-z_][\w-]*)\s*=", prior):
        if _EXAMPLE_KEY_RE.search(m.group(1)):
            return True

    # Inline comment labels within the immediate window.
    return bool(_EXAMPLE_INLINE_RE.search(prior))


# ── Curl-pipe allowlist ──────────────────────────────────────────────
# Well-known vendor installers that ship with HTTPS and publish their
# install.sh via their own CDN. A ``curl … | bash`` against one of
# these is an established idiom, not a smoking gun. Findings that
# match only against this list should be LOW-confidence, not a hard
# fail — the user should still consider cryptographic verification,
# but the finding shouldn't gate every PR that installs Docker.
_KNOWN_INSTALLERS: frozenset[str] = frozenset({
    "get.docker.com",
    "sh.rustup.rs",
    "bun.sh/install",
    "deno.land/install.sh",
    "fnm.vercel.app/install",
    "raw.githubusercontent.com/nvm-sh/nvm",    # nvm install
    "raw.githubusercontent.com/rbenv/rbenv-installer",
    "awscli.amazonaws.com/awscli-exe-linux",   # AWS CLI
    "cli.github.com/install",
    "get.helm.sh/helm",
    "get.k3s.io",
    "install.scala-lang.org",
    "install.python-poetry.org",
    "get.sdkman.io",
})


def is_known_installer(url: str) -> bool:
    """Return True when *url* matches a vendored installer on the allowlist.

    Matches by substring so query strings / path variations don't
    cause spurious misses. The allowlist is intentionally conservative
    — adding a new entry should require evidence that the installer
    uses HTTPS with cryptographic trust (either sigstore / notary or
    a published GPG key).
    """
    if not isinstance(url, str):
        return False
    url_lower = url.lower()
    return any(marker in url_lower for marker in _KNOWN_INSTALLERS)


# ── IAM Condition allow-list ─────────────────────────────────────────
# Conditions that meaningfully constrain a wildcard action or resource.
# IAM-002 / IAM-004 / IAM-006 should demote statements that carry one
# of these, since the wildcard is narrowed by the condition rather
# than being the effective grant.
_CONSTRAINING_CONDITION_KEYS: frozenset[str] = frozenset({
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalAccount",
    "aws:PrincipalArn",
    "aws:PrincipalTag",
    "aws:ResourceTag",
    "aws:ResourceAccount",
    "aws:ResourceOrgID",
    "aws:RequestTag",
    "aws:RequestedRegion",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:MultiFactorAuthPresent",
    "aws:ViaAWSService",
    "iam:PassedToService",
})


def statement_is_constrained(stmt: dict) -> bool:
    """Return True when *stmt* carries a condition that narrows scope.

    Case-insensitive match against the condition key names; IAM's key
    names are canonically PascalCase but users occasionally lowercase
    them and the policy still evaluates correctly.
    """
    conditions = stmt.get("Condition") if isinstance(stmt, dict) else None
    if not isinstance(conditions, dict):
        return False
    constraining_lower = {k.lower() for k in _CONSTRAINING_CONDITION_KEYS}
    for inner in conditions.values():
        if not isinstance(inner, dict):
            continue
        for key in inner:
            if isinstance(key, str) and key.lower() in constraining_lower:
                return True
    return False
