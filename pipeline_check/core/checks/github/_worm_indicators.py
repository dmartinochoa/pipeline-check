"""Curated registry of literal IOC strings from supply-chain worms.

Foundation for GHA-056. Where ``_compromised_actions.py`` flags
workflows pinned to a known-bad action ref and ``_malicious.py``
flags *behavioral* primitives (reverse shells, exfil channels), this
registry flags *literal post-compromise indicators*: the exact
filenames, repo names, and collector URLs that surfaced in published
worm payloads. A workflow carrying any of these is not at-risk; it is
already compromised.

Append-only. Refresh by PR with the citing vendor advisory in the
commit message. Same shape as the other curated registries: pure
data, no network at scan time.

Entries fall into three buckets:

  * ``literal`` — a fixed substring match. Cheapest, used for the
    weird-attacker-name strings (``s1ngularity-repository``,
    ``Shai-Hulud Migration``, the worm's webhook UUID).
  * ``filename`` — a path-fragment match meant to fire when a
    workflow body references the IOC filename. Used for the worm's
    own dropped ``shai-hulud-workflow.yml``.
  * ``pattern`` — a regex when the substring needs a shape (e.g.
    ``s1ngularity-repository-NNN``).

Suppression: ``_context.looks_like_example`` is applied at the rule
layer so a fixture / docs / sample / test YAML in this very repo
doesn't self-trigger on the literal IOC strings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class WormIndicator:
    """One curated worm-IOC entry.

    ``category`` is the IOC bucket (``filename`` / ``literal`` /
    ``pattern``); ``name`` is the short label that appears in the
    Finding description.
    """

    category: str
    name: str
    pattern: re.Pattern[str]
    advisory: str
    severity: Severity = Severity.CRITICAL


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. Order doesn't matter; the rule layer walks the
#: list, applies each pattern to the workflow blob, and yields every
#: hit. New entries land via PR with the citing advisory.
_REGISTRY: tuple[WormIndicator, ...] = (
    # Shai-Hulud npm worm (Sept 2025). The worm's payload wrote
    # ``.github/workflows/shai-hulud-workflow.yml`` into every
    # writable repo; that workflow then POSTed harvested secrets to
    # webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7. A workflow
    # body referencing either string is the worm's dropped file or
    # someone who hard-coded the IOC for reasons that warrant scrutiny.
    WormIndicator(
        category="filename",
        name="Shai-Hulud dropped workflow file",
        pattern=re.compile(r"\bshai-hulud(?:[-_]workflow)?\.ya?ml\b", re.IGNORECASE),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). The worm dropped "
            "``.github/workflows/shai-hulud-workflow.yml`` via a "
            "stolen GITHUB_TOKEN. "
            "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack"
        ),
    ),
    WormIndicator(
        category="literal",
        name="Shai-Hulud webhook.site collector UUID",
        pattern=re.compile(
            r"\bbb8ca5f6-4175-45d2-b042-fc9ebb8170b7\b",
            re.IGNORECASE,
        ),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). The hardcoded webhook "
            "collector UUID the worm posted stolen secrets to. "
            "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
        ),
    ),
    WormIndicator(
        category="literal",
        name="Shai-Hulud public exfil repo name",
        pattern=re.compile(
            r"\bShai-?Hulud(?:[ -](?:Migration|repository))?\b",
            re.IGNORECASE,
        ),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). Public repos named "
            "``Shai-Hulud`` / ``Shai-Hulud Migration`` were the worm's "
            "secondary exfil channel. "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/"
            "shai-hulud-2-0-guidance-for-detecting-investigating-and-"
            "defending-against-the-supply-chain-attack/"
        ),
    ),

    # Megalodon campaign (May 18, 2026). 5,718 automated commits
    # across 5,561 repos in a six-hour window (11:36-17:48 UTC).
    # Injected workflows named "SysDiag" or "Optimize-Build" with
    # base64-encoded bash payloads exfiltrating secrets to
    # 216.126.225.129:8443/collect. Throwaway accounts used 8-char
    # random usernames. Source: StepSecurity, SafeDep, SecurityWeek.
    WormIndicator(
        category="literal",
        name="Megalodon SysDiag workflow name",
        pattern=re.compile(
            r"\bSysDiag\b",
        ),
        advisory=(
            "Megalodon mass-injection campaign (May 2026). 5,718 "
            "commits across 5,500+ repos injected workflows named "
            "'SysDiag' that exfiltrated runner secrets. "
            "https://www.stepsecurity.io/blog/megalodon-mass-github-"
            "actions-secret-exfiltration-across-5-500-public-repositories"
        ),
    ),
    WormIndicator(
        category="literal",
        name="Megalodon C2 endpoint",
        pattern=re.compile(
            r"\b216\.126\.225\.129\b",
        ),
        advisory=(
            "Megalodon mass-injection campaign (May 2026). The C2 "
            "server at 216.126.225.129:8443 received gzip-compressed "
            "secret archives from compromised runners. "
            "https://safedep.io/megalodon-mass-github-repo-backdooring-"
            "ci-workflows/"
        ),
    ),
    WormIndicator(
        category="pattern",
        name="Megalodon forged commit author",
        pattern=re.compile(
            r"\b(?:build-bot@github-ci\.com|build-system@noreply\.dev|"
            r"ci-bot@automated\.dev|ci-pipeline@actions-bot\.com)\b",
            re.IGNORECASE,
        ),
        advisory=(
            "Megalodon mass-injection campaign (May 2026). Forged "
            "commit author emails used by throwaway accounts. "
            "https://safedep.io/megalodon-mass-github-repo-backdooring-"
            "ci-workflows/"
        ),
    ),

    # s1ngularity / nx (Aug 2025). The malicious postinstall walked
    # the filesystem with the help of AI CLIs (claude / gemini / q)
    # and pushed harvested secrets to new public
    # ``s1ngularity-repository*`` repos under each victim's account.
    # ``s1ngularity-repository-\d+`` is the canonical shape.
    WormIndicator(
        category="pattern",
        name="s1ngularity exfil repo name",
        pattern=re.compile(
            r"\bs1ngularity[-_]repository(?:[-_]\d+)?\b",
            re.IGNORECASE,
        ),
        advisory=(
            "Nx s1ngularity compromise (Aug 2025). Stolen secrets "
            "pushed to public ``s1ngularity-repository*`` repos under "
            "the victim's account. "
            "https://nx.dev/blog/s1ngularity-postmortem"
        ),
    ),
)


def lookup(blob: str) -> list[tuple[WormIndicator, str]]:
    """Return every ``(WormIndicator, excerpt)`` match in *blob*.

    *blob* is the workflow text (joined string fields from the parsed
    YAML, or the raw file contents — the rule layer chooses).
    Excerpt is the literal text that matched, truncated to 120
    chars so the finding description stays printable.
    """
    hits: list[tuple[WormIndicator, str]] = []
    for entry in _REGISTRY:
        for m in entry.pattern.finditer(blob):
            excerpt = m.group(0)
            if len(excerpt) > 120:
                excerpt = excerpt[:117] + "..."
            hits.append((entry, excerpt))
    return hits


def registry_size() -> int:
    """Number of registry entries. Tests consult this so a removed
    entry trips the suite."""
    return len(_REGISTRY)


def known_categories() -> frozenset[str]:
    """Set of IOC categories the registry currently covers."""
    return frozenset(e.category for e in _REGISTRY)
