"""NUGET-012. NuGet.config does not enforce signatureValidationMode = require."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig, NuGetContext

RULE = Rule(
    id="NUGET-012",
    title="NuGet.config does not enforce signatureValidationMode = require",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PROVENANCE"),
    cwe=("CWE-345", "CWE-494"),
    recommendation=(
        "Set ``signatureValidationMode`` to ``require`` in "
        "``NuGet.config`` and add at least one ``<trustedSigners>`` "
        "entry naming the authors / repositories whose packages "
        "the project will accept:\n\n"
        "    <config>\n"
        "      <add key=\"signatureValidationMode\" value=\"require\" />\n"
        "    </config>\n"
        "    <trustedSigners>\n"
        "      <author name=\"microsoft\">\n"
        "        <certificate fingerprint=\"<sha256-of-cert>\"\n"
        "                     hashAlgorithm=\"SHA256\"\n"
        "                     allowUntrustedRoot=\"false\" />\n"
        "      </author>\n"
        "      <repository name=\"nuget.org\" serviceIndex=\"https://api.nuget.org/v3/index.json\">\n"
        "        <certificate fingerprint=\"<sha256-of-cert>\"\n"
        "                     hashAlgorithm=\"SHA256\"\n"
        "                     allowUntrustedRoot=\"false\" />\n"
        "      </repository>\n"
        "    </trustedSigners>\n\n"
        "With ``require``, NuGet rejects any package whose "
        "signature doesn't validate against a trusted-signers "
        "entry — closing the substitution surface that "
        "transport-only verification leaves open. The default "
        "(``accept``) verifies signatures when present but "
        "happily accepts unsigned packages, which means a "
        "compromised mirror serving unsigned drop-ins isn't "
        "rejected at restore time."
    ),
    docs_note=(
        "Reads each ``NuGet.config``'s ``<config>`` block for "
        "``signatureValidationMode``. Fires when the key is "
        "absent (default is ``accept``) or set to anything other "
        "than ``require`` (case-insensitive). The rule does NOT "
        "verify that ``<trustedSigners>`` is populated when "
        "``require`` is set; a follow-up rule can audit the "
        "signers' completeness.\n\n"
        "Distinct from NUGET-010 (cleartext credentials) and "
        "NUGET-007 (package-source mapping): those audit credential "
        "and routing posture; this rule audits the integrity-"
        "verification posture at install time."
    ),
    known_fp=(
        "Internal-only NuGet feeds where every package is "
        "trusted by the workspace's perimeter posture (a single "
        "internal Nexus that the operator controls end-to-end) "
        "may legitimately accept unsigned packages. Suppress per "
        "config with a one-line rationale; production-facing "
        "workspaces should require signatures.",
    ),
    incident_refs=(
        ".NET supply-chain compromise pattern: a popular package "
        "is published with a slight name variant via a "
        "compromised maintainer account. The original package is "
        "signed; the variant isn't. Consumers with "
        "``signatureValidationMode=accept`` install both without "
        "distinction; ``require`` mode rejects the unsigned "
        "variant at restore time.",
    ),
    exploit_example=(
        "<!-- Vulnerable: signature validation in default mode. -->\n"
        "<configuration>\n"
        "  <config>\n"
        "    <!-- (signatureValidationMode not set; default = accept) -->\n"
        "  </config>\n"
        "  <packageSources>\n"
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
        "  </packageSources>\n"
        "</configuration>\n"
        "\n"
        "<!-- Attack: a compromised mirror serves an unsigned\n"
        "     drop-in for a popular package. NuGet restore\n"
        "     accepts it because ``accept`` mode treats missing\n"
        "     signatures as OK.\n"
        "-->\n"
        "\n"
        "<!-- Safe: require mode + explicit trusted signers. -->\n"
        "<configuration>\n"
        "  <config>\n"
        "    <add key=\"signatureValidationMode\" value=\"require\" />\n"
        "  </config>\n"
        "  <trustedSigners>\n"
        "    <repository name=\"nuget.org\" serviceIndex=\"...\">\n"
        "      <certificate fingerprint=\"...\" hashAlgorithm=\"SHA256\" />\n"
        "    </repository>\n"
        "  </trustedSigners>\n"
        "</configuration>"
    ),
)


_MSBUILD_NS = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _signature_mode(cfg_path: str) -> str | None:
    """Re-parse the file to read ``<config>`` -> ``signatureValidationMode``.
    Returns the value (lowercased) or ``None`` when absent."""
    try:
        tree = ET.parse(cfg_path)
    except (ET.ParseError, OSError):
        return None
    root = tree.getroot()
    for child in root:
        if _strip_ns(child.tag) == "config":
            for entry in child:
                if _strip_ns(entry.tag) != "add":
                    continue
                key = entry.get("key", "").lower()
                if key == "signaturevalidationmode":
                    value = entry.get("value", "").strip().lower()
                    return value or None
    return None


def check(cfg: NuGetConfig, ctx: NuGetContext) -> Finding:
    # Resolve relative paths against the scan root; the loader
    # stores ``cfg.path`` as a path relative to the scan input.
    cfg_path = Path(cfg.path)
    if not cfg_path.is_absolute() and ctx.scan_root is not None:
        cfg_path = ctx.scan_root / cfg_path
    mode = _signature_mode(str(cfg_path))
    if mode == "require":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "NuGet.config enforces signatureValidationMode = "
                "require."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    actual = (
        "absent (default = accept)" if mode is None
        else f"set to {mode!r}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path,
        description=(
            f"signatureValidationMode is {actual}. Unsigned "
            f"packages and packages with broken signatures are "
            f"accepted at restore time; a compromised mirror "
            f"serving unsigned drop-ins isn't rejected."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
