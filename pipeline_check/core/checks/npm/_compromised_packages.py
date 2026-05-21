"""Curated registry of known-compromised npm packages.

Foundation for NPM-006 — a pure-data table of ``(name,
malicious_versions, advisory)`` entries sourced from public CVEs,
GHSAs, and vendor postmortems. The rule consults this registry to
detect lockfile entries pinned to a known-bad version (the
post-incident detection angle that complements NPM-001's floating-
range prevention and NPM-002's integrity-hash verification).

Mirrors the shape of ``pipeline_check.core.checks.github.
_compromised_actions``: hand-curated, append-only, refresh by PR
with the citing advisory in the commit message. Deliberately NOT a
fetch-from-network registry — pulling the list on every scan would
take the "no telemetry, no API tokens" default off the table.

Each entry captures:

  * ``name`` — npm package name (lower-cased; scope preserved as
    ``@scope/name``).
  * ``malicious_versions`` — tuple of exact version literals.
    Comparison is case-sensitive string equality; npm version
    strings are already lower-case in practice.
  * ``version_pattern`` — optional ``re.Pattern`` matched when no
    literal entry catches the version. Used for advisories that
    span a range ("all versions before X.Y.Z were rebuilt with
    backdoor").
  * ``advisory`` — one-line citation. CVE / GHSA / vendor URL.
  * ``severity`` — per-entry severity. CRITICAL for active
    credential-stealer / RCE compromises; HIGH for protestware /
    self-sabotage cases where the payload is destructive but
    scoped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .._primitives.compromised import match_version
from ..base import Severity


@dataclass(frozen=True, slots=True)
class CompromisedPackage:
    """One curated npm-package-compromise entry."""

    name: str
    malicious_versions: tuple[str, ...]
    advisory: str
    severity: Severity = Severity.CRITICAL
    version_pattern: re.Pattern[str] | None = None

    def matches(self, version: str) -> bool:
        return match_version(
            version,
            malicious_versions=self.malicious_versions,
            version_pattern=self.version_pattern,
        )


# ── Curated registry ─────────────────────────────────────────────────


#: Append-only list. Order doesn't matter (lookup is by name); the
#: rule layer iterates entries that match a lockfile / manifest
#: dependency name. New entries land via PR with the citing
#: advisory in the commit message.
_REGISTRY: tuple[CompromisedPackage, ...] = (
    # event-stream compromise (November 2018). Attacker (right9ctrl)
    # took over maintenance from dominictarr, then added a malicious
    # ``flatmap-stream`` dependency targeting Copay wallet builds.
    # Discovered when a downstream user noticed the new transitive.
    # Public postmortem at github.com/dominictarr/event-stream/issues/116.
    CompromisedPackage(
        name="event-stream",
        malicious_versions=("3.3.6",),
        advisory=(
            "event-stream 3.3.6 (Nov 2018): malicious ``flatmap-stream`` "
            "transitive added by hijacked maintainer; targeted Copay "
            "wallet builds. "
            "https://github.com/dominictarr/event-stream/issues/116"
        ),
    ),

    # ua-parser-js compromise (October 2021). Attacker hijacked the
    # publisher's npm account and pushed malicious versions that
    # installed a crypto miner + password stealer via postinstall.
    # CVE-2021-43547 / GHSA-pjwm-rvh2-c87w.
    CompromisedPackage(
        name="ua-parser-js",
        malicious_versions=("0.7.29", "0.8.0", "1.0.0"),
        advisory=(
            "CVE-2021-43547 / GHSA-pjwm-rvh2-c87w: ua-parser-js "
            "compromise (Oct 2021). Hijacked maintainer account; "
            "postinstall installed XMRig miner + DanaBot stealer. "
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w"
        ),
    ),

    # coa compromise (November 2021). Same campaign as rc (below);
    # attacker hijacked the maintainer account and re-published with
    # a credential stealer in postinstall. GHSA-73qr-pfmq-6rp8.
    CompromisedPackage(
        name="coa",
        malicious_versions=("2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"),
        advisory=(
            "GHSA-73qr-pfmq-6rp8: coa compromise (Nov 2021). "
            "Maintainer-account takeover; postinstall installed a "
            "credential stealer. "
            "https://github.com/advisories/GHSA-73qr-pfmq-6rp8"
        ),
    ),

    # rc compromise (November 2021). Same campaign as coa.
    # GHSA-g2q5-5433-rhrf.
    CompromisedPackage(
        name="rc",
        malicious_versions=("1.2.9", "1.3.9", "2.3.9"),
        advisory=(
            "GHSA-g2q5-5433-rhrf: rc compromise (Nov 2021). Same "
            "campaign as coa; credential-stealer in postinstall. "
            "https://github.com/advisories/GHSA-g2q5-5433-rhrf"
        ),
    ),

    # node-ipc protestware (March 2022). Maintainer added a payload
    # that wiped files on hosts geo-located to Russia / Belarus,
    # framed as a war protest. CVE-2022-23812. Severity HIGH (not
    # CRITICAL) since the payload is destructive-on-condition rather
    # than a covert credential stealer; SOC2 / supply-chain reviews
    # still treat any version in the affected range as poisoned.
    CompromisedPackage(
        name="node-ipc",
        malicious_versions=("10.1.1", "10.1.2", "10.1.3"),
        advisory=(
            "CVE-2022-23812: node-ipc protestware (Mar 2022). "
            "Geographic-conditional file-wipe payload added by "
            "maintainer; affects 10.1.1-10.1.3. Treat any 11.x "
            "publish window cautiously, the same author retained "
            "publish rights. "
            "https://nvd.nist.gov/vuln/detail/CVE-2022-23812"
        ),
        severity=Severity.HIGH,
    ),

    # @ledgerhq/connect-kit compromise (December 2023). Phishing of a
    # former Ledger employee whose npm publish rights had not been
    # revoked; attacker shipped Angel Drainer in the wallet-UI loader.
    # ~$700k stolen in a ~5-hour window before npm pulled the versions.
    CompromisedPackage(
        name="@ledgerhq/connect-kit",
        malicious_versions=("1.1.5", "1.1.6", "1.1.7"),
        advisory=(
            "Ledger Connect Kit compromise (Dec 2023). Phished "
            "ex-employee account republished the wallet UI loader "
            "with Angel Drainer; dApps on floating ranges drained "
            "for ~5 hours. "
            "https://www.ledger.com/blog/security-incident-report"
        ),
    ),

    # @solana/web3.js backdoor (CVE-2024-54134, December 2024). Spear-
    # phish of a @solana publisher via the npnjs.com typosquat clone;
    # malicious versions added an addToQueue() that wrapped private-key
    # handling and exfiltrated keys inside fake Cloudflare cf-ipinfo
    # HTTP headers.
    CompromisedPackage(
        name="@solana/web3.js",
        malicious_versions=("1.95.6", "1.95.7"),
        advisory=(
            "CVE-2024-54134 / GHSA-jcxm-7wvp-g6p5: @solana/web3.js "
            "(Dec 2024). Phish-driven publisher takeover; private-key "
            "exfil via fake cf-ipinfo HTTP headers. "
            "https://github.com/solana-labs/solana-web3.js/security/"
            "advisories/GHSA-jcxm-7wvp-g6p5"
        ),
    ),

    # @lottiefiles/lottie-player compromise (October 2024). Phished
    # LottieFiles employee npm account republished the loader with a
    # Web3Modal-keyed wallet drainer; trigger domain
    # ``castleservices01.com``.
    CompromisedPackage(
        name="@lottiefiles/lottie-player",
        malicious_versions=("2.0.5", "2.0.6", "2.0.7"),
        advisory=(
            "LottieFiles Lottie Player compromise (Oct 2024). "
            "Phished employee account republished the loader with a "
            "Web3Modal wallet drainer. "
            "https://snyk.io/blog/lottie-player-npm-package-"
            "compromised-crypto-wallet-theft/"
        ),
    ),

    # @rspack/core, @rspack/cli compromise (December 2024). Stolen
    # npm tokens (suspected CI log leak); postinstall fetched and
    # launched XMRig.
    CompromisedPackage(
        name="@rspack/core",
        malicious_versions=("1.1.7",),
        advisory=(
            "rspack compromise (Dec 2024). Stolen npm token; "
            "postinstall fetched XMRig. "
            "https://socket.dev/blog/rspack-supply-chain-attack"
        ),
    ),
    CompromisedPackage(
        name="@rspack/cli",
        malicious_versions=("1.1.7",),
        advisory=(
            "rspack compromise (Dec 2024). Stolen npm token; "
            "postinstall fetched XMRig. "
            "https://socket.dev/blog/rspack-supply-chain-attack"
        ),
    ),

    # vant compromise (December 2024). Same campaign as rspack;
    # ten versions across the 2.x / 3.x / 4.x branches shipped the
    # XMRig postinstall.
    CompromisedPackage(
        name="vant",
        malicious_versions=(
            "2.13.3", "2.13.4", "2.13.5",
            "3.6.13", "3.6.14", "3.6.15",
            "4.9.11", "4.9.12", "4.9.13", "4.9.14",
        ),
        advisory=(
            "vant compromise (Dec 2024). Stolen npm token; "
            "postinstall fetched XMRig across 2.x / 3.x / 4.x. "
            "https://www.bleepingcomputer.com/news/security/"
            "malicious-rspack-vant-packages-published-using-stolen"
            "-npm-tokens/"
        ),
    ),

    # nx & @nx/* s1ngularity compromise (August 2025). PR-title
    # script-injection on a stale branch yielded the npm publish
    # token; ~4 hours of malicious publishes that abused AI CLIs
    # (claude / gemini / q) to harvest filesystem secrets and pushed
    # them to public ``s1ngularity-repository*`` repos under each
    # victim's account.
    CompromisedPackage(
        name="nx",
        malicious_versions=(
            "20.9.0", "20.10.0", "20.11.0", "20.12.0",
            "21.5.0", "21.6.0", "21.7.0", "21.8.0",
        ),
        advisory=(
            "Nx s1ngularity compromise (Aug 2025). PR-title injection "
            "stole the publish token; postinstall abused claude/gemini/q "
            "CLIs to harvest secrets to public s1ngularity-repository* "
            "repos. https://nx.dev/blog/s1ngularity-postmortem"
        ),
    ),

    # eslint-config-prettier + ecosystem (CVE-2025-54313, July 2025).
    # Phish from support@npmjs.org → npnjs.com clone produced
    # publish-token takeovers for several adjacent packages; the
    # Scavenger infostealer was bundled via install.js / node-gyp.dll
    # on Windows.
    CompromisedPackage(
        name="eslint-config-prettier",
        malicious_versions=("8.10.1", "9.1.1", "10.1.6", "10.1.7"),
        advisory=(
            "CVE-2025-54313: eslint-config-prettier (Jul 2025). "
            "npnjs.com phish-driven account takeover; install.js + "
            "node-gyp.dll deployed the Scavenger infostealer on "
            "Windows. https://zeropath.com/blog/cve-2025-54313-"
            "eslint-config-prettier-supply-chain-malware"
        ),
    ),
    CompromisedPackage(
        name="eslint-plugin-prettier",
        malicious_versions=("4.2.2", "4.2.3"),
        advisory=(
            "CVE-2025-54313 campaign (Jul 2025). Same phish; sibling "
            "package republished with the Scavenger infostealer."
        ),
    ),
    CompromisedPackage(
        name="synckit",
        malicious_versions=("0.11.9",),
        advisory=(
            "CVE-2025-54313 campaign (Jul 2025). Same phish; sibling "
            "package republished with the Scavenger infostealer."
        ),
    ),
    CompromisedPackage(
        name="@pkgr/core",
        malicious_versions=("0.2.8",),
        advisory=(
            "CVE-2025-54313 campaign (Jul 2025). Same phish; sibling "
            "package republished with the Scavenger infostealer."
        ),
    ),
    CompromisedPackage(
        name="napi-postinstall",
        malicious_versions=("0.3.1",),
        advisory=(
            "CVE-2025-54313 campaign (Jul 2025). Same phish; sibling "
            "package republished with the Scavenger infostealer."
        ),
    ),

    # Shai-Hulud npm worm (Sept 2025). ~180-300 packages republished
    # by a self-replicating worm that ran TruffleHog in postinstall
    # and pushed stolen secrets to public Shai-Hulud / *-Migration
    # repos under each victim's account. The registry below carries
    # the highest-traffic affected names verified by Wiz / Microsoft /
    # Unit42; the full IOC list is too large for a curated registry
    # and is best consumed from the live OSV feed. Operators wanting
    # the long tail should cross-reference the Microsoft advisory.
    CompromisedPackage(
        name="@ctrl/tinycolor",
        malicious_versions=("4.1.1", "4.1.2"),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). Self-replicating worm "
            "across ~180 packages; postinstall ran TruffleHog and "
            "pushed loot to public Shai-Hulud repos. "
            "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack"
        ),
    ),
    CompromisedPackage(
        name="@ctrl/deluge",
        malicious_versions=("7.2.2",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="@ctrl/golang-template",
        malicious_versions=("1.4.3",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="@ctrl/magnet-link",
        malicious_versions=("4.0.4",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="@crowdstrike/commitlint",
        malicious_versions=("8.1.1", "8.1.2"),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). @crowdstrike-scoped "
            "packages republished by the worm. See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="@crowdstrike/falcon-shoelace",
        malicious_versions=("0.4.2",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="@crowdstrike/foundry-js",
        malicious_versions=("0.19.2",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="ngx-bootstrap",
        malicious_versions=("18.1.4", "19.0.3", "19.0.4", "20.0.3", "20.0.4", "20.0.5"),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="rxnt-authentication",
        malicious_versions=("0.0.6",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
    CompromisedPackage(
        name="rxnt-healthchecks-nestjs",
        malicious_versions=("1.0.5",),
        advisory=(
            "Shai-Hulud npm worm (Sept 2025). See @ctrl/tinycolor."
        ),
    ),
)


def lookup(name: str, version: str) -> CompromisedPackage | None:
    """Return the matching :class:`CompromisedPackage` or ``None``.

    Match logic: case-insensitive on package name (scopes preserved),
    exact on version literal or regex-via-``version_pattern``. Returns
    the first matching registry entry.
    """
    n_lc = name.lower()
    for entry in _REGISTRY:
        if entry.name.lower() != n_lc:
            continue
        if not entry.malicious_versions and entry.version_pattern is None:
            continue
        if entry.matches(version):
            return entry
    return None


def registry_size() -> int:
    """Number of registry entries. Tests consult this so a removed
    entry trips the suite."""
    return len(_REGISTRY)


def known_names() -> frozenset[str]:
    """Set of (lower-cased) package names the registry covers."""
    return frozenset(e.name.lower() for e in _REGISTRY)
