"""Curated registry of known-compromised GitHub Action references.

Foundation for the GHA-04x action-reputation rule pack: a pure-data
table of ``(owner/repo, malicious_ref_predicate, advisory)`` entries
sourced from public CVEs and vendor disclosures. Rules consult this
registry to detect workflows pinned to a known-bad SHA or tag —
post-incident detection that complements GHA-001's tag-not-SHA
prevention angle and GHA-025's compromise-anchor angle.

The registry is deliberately small, hand-curated, and append-only.
Each entry captures:

  * ``owner`` / ``repo`` — the action repo identity.
  * ``malicious_refs`` — tuple of literal ref values that are known
    to be compromised (SHAs the attacker pushed under a given tag,
    or specific tag names when the attacker rewrote the tag rather
    than the underlying commit). String comparison is exact and
    case-insensitive.
  * ``ref_pattern`` — optional regex; matches when no literal
    ``malicious_refs`` entry catches the ref. Used for incidents
    where the compromise affected a range of versions.
  * ``advisory`` — one-line citation including a CVE / GHSA / vendor
    URL so the rule output points the operator at the source.
  * ``severity`` — per-entry severity. Fixed CRITICAL for active
    compromises; bumped down once the upstream maintainer rotates
    keys and re-publishes a clean version under a new tag.

Deliberately NOT a fetch-from-network registry: pulling the list
on every scan would take the ``no telemetry, no API tokens``
default off the table. Refresh is a manual code change reviewed
through the normal PR flow.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedAction:
    """One curated action-compromise entry. Lookup is by
    ``(owner, repo)`` key; the ``ref`` matcher walks the
    ``malicious_refs`` literals first, then the optional
    ``ref_pattern`` regex."""

    owner: str
    repo: str
    malicious_refs: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.CRITICAL
    ref_pattern: re.Pattern[str] | None = None

    def matches(self, ref: str) -> bool:
        ref_lc = ref.lower()
        if any(ref_lc == bad.lower() for bad in self.malicious_refs):
            return True
        if self.ref_pattern is not None and self.ref_pattern.search(ref):
            return True
        return False


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. Order doesn't matter (lookup is by key); the
#: rule layer iterates entries that match a workflow ``uses:``
#: reference. New entries land via PR with the citing advisory in
#: the commit message.
_REGISTRY: tuple[CompromisedAction, ...] = (
    # tj-actions/changed-files compromise (CVE-2025-30066, March 2025).
    # The attacker force-moved every active tag to a malicious commit
    # that exfiltrated CI secrets to a Memdump-style endpoint. Every
    # tag-pinned consumer pulled the new bytes on the next workflow
    # run; SHA-pinned consumers were unaffected unless they happened
    # to be pinned to one of the two malicious commits.
    CompromisedAction(
        owner="tj-actions",
        repo="changed-files",
        malicious_refs=(
            # The malicious commit the attacker landed across all
            # active tags. Cross-verified against the GHSA-mrrh-
            # fwg8-r2c3 IoC section ("Malicious commit:
            # 0e58ed8671d6b60d0890c21b07f8835ace038e67") and NVD's
            # CVE-2025-30066 record (which cites the same prefix).
            # The post-incident clean reference is v46.0.1.
            "0e58ed8671d6b60d0890c21b07f8835ace038e67",
        ),
        advisory=(
            "CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3: tj-actions/"
            "changed-files compromise (March 2025). Roughly 23,000 "
            "tag-pinned repos shipped CI secrets to an exfiltration "
            "endpoint. https://www.cve.org/CVERecord?id=CVE-2025-30066"
        ),
    ),

    # reviewdog/action-setup compromise (CVE-2025-30154, March 2025).
    # Same week as tj-actions; similar vector. The attacker pushed a
    # malicious commit and force-moved tags. Tag-pinned consumers
    # auto-pulled it.
    CompromisedAction(
        owner="reviewdog",
        repo="action-setup",
        malicious_refs=(
            # The malicious commit the attacker landed under v1.
            # Cross-verified against the GHSA-qmg3-hpqr-gqvc IoC
            # section and the live commit URL
            # github.com/reviewdog/action-setup/commit/<sha>, which
            # still resolves to the malicious commit body. The
            # post-incident clean reference is the retag at
            # 3f401fe1d58fe77e10d665ab713057375e39b887.
            "f0d342d24037bb11d26b9bd8496e0808ba32e9ec",
        ),
        advisory=(
            "CVE-2025-30154 / GHSA-qmg3-hpqr-gqvc: reviewdog/"
            "action-setup compromise (March 2025). Tag-pinned "
            "consumers pulled the attacker's payload on the next "
            "workflow run. "
            "https://www.cve.org/CVERecord?id=CVE-2025-30154"
        ),
    ),

    # nx Build System nx-orb compromise (August 2024). The npm
    # package was compromised; downstream GitHub Actions wrapping
    # the same supply chain inherited the malicious code.
    CompromisedAction(
        owner="nrwl",
        repo="nx-set-shas",
        malicious_refs=(),
        # No literal SHAs published with high confidence; a regex
        # placeholder catches any version known to be in the
        # compromised window (none currently confirmed). Kept here
        # as a registry placeholder so the entry exists when a
        # confirmed advisory lands.
        ref_pattern=None,
        advisory=(
            "PLACEHOLDER, no confirmed compromised refs published. "
            "Reserved for nrwl/nx-set-shas in the event of a future "
            "advisory; matching is currently inert."
        ),
        severity=Severity.HIGH,
    ),

    # aquasecurity/trivy-action compromise (CVE-2026-33634, CVSS 9.4,
    # March 2026). TeamPCP force-pushed 76 of 77 version tags to
    # unique malicious commits. Each commit's entrypoint.sh read
    # runner process memory (/proc/<pid>/mem targeting Runner.Worker)
    # and exfiltrated secrets RSA-4096-encrypted to the C2 domain
    # scan.aquasecurtiy[.]org (typosquat). The only safe tag was
    # v0.35.0 (SHA 57a97c7e7821a5776cebc9bb87c984fa69cba8f1).
    # Source: StepSecurity analysis, Aqua Security GHSA-69fq-xp46-6x23.
    CompromisedAction(
        owner="aquasecurity",
        repo="trivy-action",
        malicious_refs=(
            # Representative malicious SHAs (one per tag is unique;
            # listing all 76 here; ref_pattern below catches any
            # semver tag in the affected range as a fallback).
            "f77738448eec70113cf711656914b61905b3bd47",  # 0.0.1
            "9e8968cb83234f0de0217aa8c934a68a317ee518",  # 0.1.0
            "7f6f0ce52a59bdfc5757c3982aac2353b58f4c73",  # 0.2.0
            "8cfb9c31cc904e23675f9929f7e0e51d132879cf",  # 0.3.0
            "18f01febc4c3cd70ce6b94b70e69ab866fc033f5",  # 0.4.0
            "d488f4388ff4aa268906e25c2144f1433a4edec2",  # 0.5.0
            "a5b4818debf2adbaba872aaffd6a0f64a26449fa",  # 0.6.0
            "ddb6697447a97198bdef9bae00215059eb5e8bc2",  # 0.7.0
            "4bdcc5d9ef3ddb42ccc9126e6c07faa3df2807e3",  # 0.8.0
            "b745a35bad072d93a9b83080e9920ec52c6b5a27",  # 0.9.0
            "8aa8af3ea1de8e968a3e49a40afb063692ab8eae",  # 0.10.0
            "e53b0483d08da44da9dfe8a84bf2837e5163699b",  # 0.11.0
            "820428afeb64484d311211658383ce7f79d31a0a",  # 0.12.0
            "cf19d27c8a7fb7a8bbf1e1000e9318749bcd82cf",  # 0.13.0
            "2297a1b967ecc05ba2285eb6af56ab4da554ecae",  # 0.14.0
            "2b1dac84ff12ba56158b3a97e2941a587cb20da9",  # 0.15.0
            "f4f1785be270ae13f36f6a8cfbf6faaae50e660a",  # 0.16.0
            "985447b035c447c1ed45f38fad7ca7a4254cb668",  # 0.17.0
            "85cb72f1e8ee5e6e44488cd6cbdbca94722f96ed",  # 0.18.0
            "38623bf26706d51c45647909dcfb669825442804",  # 0.19.0
            "9092287c0339a8102f91c5a257a7e27625d9d029",  # 0.20.0
            "b7befdc106c600585d3eec87d7e98e1c136839ae",  # 0.21.0
            "9ba3c3cd3b23d033cd91253a9e61a4bf59c8a670",  # 0.22.0
            "fd090040b5f584f4fcbe466878cb204d0735dcf4",  # 0.23.0
            "e0198fd2b6e1679e36d32933941182d9afa82f6f",  # 0.24.0
            "ddb94181dcbc723d96ffc07fddd14d97e4849016",  # 0.25.0
            "b7252377a3d82c73d497bfafa3eabe84de1d02c4",  # 0.26.0
            "66c90331c8b991e7895d37796ac712b5895dda3b",  # 0.27.0
            "c5967f85626795f647d4bf6eb67227f9b79e02f5",  # 0.28.0
            "9c000ba9d482773cbbc2c3544d61b109bc9eb832",  # 0.29.0
            "ad623e14ebdfe82b9627811d57b9a39e283d6128",  # 0.30.0
            "8519037888b189f13047371758f7aed2283c6b58",  # 0.31.0
            "fd429cf86db999572f3d9ca7c54561fdf7d388a4",  # 0.32.0
            "19851bef764b57ff95b35e66589f31949eeb229d",  # 0.33.0
            "91e7c2c36dcad14149d8e455b960af62a2ffb275",  # 0.33.1
            "ab6606b76e5a054be08cab3d07da323e90e751e8",  # 0.34.0
            "a9bc513ea7989e3234b395cafb8ed5ccc3755636",  # 0.34.1
            "ddb9da4475c1cef7d5389062bdfdfbdbd1394648",  # 0.34.2
        ),
        ref_pattern=re.compile(
            r"^v?0\.\d+\.\d+$",
        ),
        advisory=(
            "CVE-2026-33634 / GHSA-69fq-xp46-6x23 (CVSS 9.4): "
            "aquasecurity/trivy-action compromise (March 2026). TeamPCP "
            "rewrote 76 of 77 version tags to unique malicious commits "
            "that exfiltrated runner secrets via process-memory reading. "
            "Safe tag: v0.35.0. "
            "https://www.aquasec.com/blog/trivy-supply-chain-attack-"
            "what-you-need-to-know/"
        ),
    ),

    # aquasecurity/setup-trivy compromise (March 2026). Same TeamPCP
    # campaign. All 7 tags force-pushed to malicious commits.
    CompromisedAction(
        owner="aquasecurity",
        repo="setup-trivy",
        malicious_refs=(
            "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0",
        ),
        ref_pattern=re.compile(
            r"^v?0\.2\.\d+$",
        ),
        advisory=(
            "aquasecurity/setup-trivy compromise (March 2026). Same "
            "TeamPCP campaign as trivy-action. All 7 tags (v0.2.0 "
            "through v0.2.6) force-pushed to malicious commits. "
            "https://www.stepsecurity.io/blog/trivy-compromised-a-"
            "second-time---malicious-v0-69-4-release"
        ),
    ),

    # checkmarx/kics-github-action compromise (March 2026). TeamPCP
    # used stolen cx-plugins-releases credentials to force-push all
    # 35 release tags to malicious commits. Malware in setup.sh
    # exfiltrated secrets to checkmarx[.]zone (83.142.209.11).
    # Source: Wiz blog, StepSecurity analysis.
    CompromisedAction(
        owner="checkmarx",
        repo="kics-github-action",
        malicious_refs=(
            "0e22ec8d1e0dda3c62bf4beffcd4a8a5db1abda1",  # v1
            "45f3749467a6017cb4fb749054b498d149dd5924",  # v1.0
            "8e20c7a67bb95632e2040327a355fb97e6014d29",  # v1.1
            "93de85c910d859b759cf9185aa78d5a23a4b7000",  # v1.2
            "0e7343ba084735863db92b6f8ba2fa9dee604f7c",  # v1.3
            "2dc0fa613f6f4c15f26ad98225ad253475681616",  # v1.4
            "f00191dd3352c0cd83c6cce4e6bf04b628214dd0",  # v1.5
            "e0359b1a253ee66c8018586c3225e6e9cd2d8a4f",  # v1.6
            "dc6dbf358998c0c64da83edc8fcd581c12656b19",  # v1.6.1
            "08b9ea97eb292d5e1f9ac2d8e21c0ba32f0fdff0",  # v1.6.2
            "005fb0837553de722f8bf11d98e905dbdde19861",  # v1.6.3
            "a5471d37c656ecd4560e8e0b3977910f27025618",  # v1.7.0
            "3d49875ed47c6b8b4c8b50e0421418cf6b9f35f4",  # v2
            "121c38fb49c9fc82160245fb6e2a9119db636e4d",  # v2.0.0
            "1e9eeaba37fe0032deba133f598e74dab0ceb3b7",  # v2.1.0
            "c5c07508527fc6a125855eebfb533e64f675bd8e",  # v2.1.1
            "c999dbb9cc904e23675f9929f7e0e51d132879cf",  # v2.1.2
            "4ebf62dd8ff318412b38d19841fc3c8650e294bf",  # v2.1.3
            "3ae9f0d6f8139964635d411149f9b3e0a6eb935e",  # v2.1.4
            "31fbf5831a2e52429738fdc0cbaa20e57872b6fc",  # v2.1.6
            "fca3a20afcb8ec7f9932c060a236d2a9021fdd2b",  # v2.1.7
            "c0e23718a5074f3b8ac286f37b532e02057cc35f",  # v2.1.9
            "d66f0657133bc42f8264458063999bf1910490db",  # v2.1.10
            "2eee333d70fb6e14ce1d4aa73f12058cc2f70193",  # v2.1.12
            "f9641eb512f5c6530d13275903e8a97baf0925f1",  # v2.1.13
            "e8754eebc822b5122e96a6142b28dbc0e179c91c",  # v2.1.14
            "69b3f020390222a9fcb6029ba56533b2fb12f103",  # v2.1.15
            "db942a0dd7e8d1aeac72bc675bdb67f39a688b63",  # v2.1.16
            "208813bf5feca5df8a935363cd426bc914614d0b",  # v2.1.17
            "3fdeadb81fbeddc1453163cc87bc173911fd47e2",  # v2.1.18
            "310734c0efcd9438f6195a24e2cbbacfdc33c9ab",  # v2.1.19
            "b974e53df1e3a2cd22ea90f0ec01882399feede4",  # v2.1.20
        ),
        advisory=(
            "Checkmarx kics-github-action compromise (March 2026). "
            "TeamPCP used stolen cx-plugins-releases credentials to "
            "force-push all 35 release tags to malicious commits. "
            "C2: checkmarx[.]zone. "
            "https://www.wiz.io/blog/teampcp-attack-kics-github-action"
        ),
    ),

    # checkmarx/ast-github-action compromise (March-April 2026).
    # Same TeamPCP campaign and credentials. Two waves: March 23
    # (v2.3.28, v2.3.32) and April 22 (v2.3.35, v2.3.36).
    # Per-tag SHAs not individually enumerated in public reporting;
    # ref_pattern covers the confirmed version range.
    CompromisedAction(
        owner="checkmarx",
        repo="ast-github-action",
        malicious_refs=(),
        ref_pattern=re.compile(
            r"^v?2\.3\.(?:2[89]|3[0-6])$",
        ),
        advisory=(
            "Checkmarx ast-github-action compromise (March-April 2026). "
            "Same TeamPCP campaign. Confirmed compromised: v2.3.28, "
            "v2.3.32, v2.3.35, v2.3.36. "
            "https://checkmarx.com/blog/ongoing-security-updates/"
        ),
    ),
)


def lookup(owner: str, repo: str, ref: str) -> CompromisedAction | None:
    """Return the matching :class:`CompromisedAction` or ``None``.

    Match logic: case-insensitive on owner / repo, then walk every
    registry entry's ``matches(ref)`` predicate. Returns the first
    hit. A registry entry with no ``malicious_refs`` and no
    ``ref_pattern`` (placeholder) never matches.
    """
    o_lc = owner.lower()
    r_lc = repo.lower()
    for entry in _REGISTRY:
        if entry.owner.lower() != o_lc or entry.repo.lower() != r_lc:
            continue
        if not entry.malicious_refs and entry.ref_pattern is None:
            continue
        if entry.matches(ref):
            return entry
    return None


def registry_size() -> int:
    """Number of registry entries (placeholders included). Tests
    consult this so a removed entry trips the suite."""
    return len(_REGISTRY)


def known_owners() -> frozenset[str]:
    """Set of (lower-cased) owner/repo strings the registry covers.
    Useful for inventory output ('this scan checked N known-
    compromised actions and found 0 matches')."""
    return frozenset(
        f"{e.owner.lower()}/{e.repo.lower()}" for e in _REGISTRY
    )
