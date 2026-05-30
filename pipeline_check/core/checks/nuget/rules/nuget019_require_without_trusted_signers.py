"""NUGET-019. signatureValidationMode=require with no trusted signers."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig, NuGetContext

RULE = Rule(
    id="NUGET-019",
    title="signatureValidationMode=require with no trusted signers",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS", "ESF-S-PROVENANCE"),
    cwe=("CWE-345", "CWE-494"),
    recommendation=(
        "When ``signatureValidationMode`` is ``require``, add at "
        "least one ``<trustedSigners>`` entry with a certificate so "
        "there is something to validate signatures against:\n\n"
        "    <config>\n"
        "      <add key=\"signatureValidationMode\" value=\"require\" />\n"
        "    </config>\n"
        "    <trustedSigners>\n"
        "      <repository name=\"nuget.org\"\n"
        "                  serviceIndex=\"https://api.nuget.org/v3/index.json\">\n"
        "        <certificate fingerprint=\"<sha256-of-cert>\"\n"
        "                     hashAlgorithm=\"SHA256\"\n"
        "                     allowUntrustedRoot=\"false\" />\n"
        "      </repository>\n"
        "    </trustedSigners>\n\n"
        "``require`` only rejects untrusted packages when there is a "
        "populated signer list to validate against. With "
        "``require`` set but ``<trustedSigners>`` empty or absent, "
        "NuGet has no anchor to check signatures against, so the "
        "integrity guarantee the mode is supposed to provide doesn't "
        "actually hold."
    ),
    docs_note=(
        "The follow-up to NUGET-012. NUGET-012 fires when "
        "``signatureValidationMode`` is not ``require``; this rule "
        "fires for the opposite, narrower case: the mode IS "
        "``require`` but ``<trustedSigners>`` is missing or carries "
        "no ``<certificate>`` under any ``<author>`` / "
        "``<repository>`` entry. The rule re-reads the file to "
        "inspect ``<config>`` and ``<trustedSigners>``. When the "
        "mode is anything other than ``require`` the rule passes and "
        "leaves the finding to NUGET-012."
    ),
    known_fp=(
        "A config that inherits ``<trustedSigners>`` from a "
        "machine-level or parent ``NuGet.config`` looks empty here "
        "but validates correctly at restore time. The rule reads a "
        "single file, so it can't see inherited signers. Suppress "
        "per config with a one-line rationale pointing at the parent "
        "config that supplies the signers.",
    ),
    incident_refs=(
        ".NET supply-chain hardening guidance: teams enable "
        "``signatureValidationMode=require`` expecting it to reject "
        "unsigned or untrusted packages, but without a populated "
        "``<trustedSigners>`` list the setting has no trust anchor "
        "to enforce against, so the protection is silently a no-op.",
    ),
    exploit_example=(
        "<!-- Vulnerable: require mode, but no trusted signers. -->\n"
        "<configuration>\n"
        "  <config>\n"
        "    <add key=\"signatureValidationMode\" value=\"require\" />\n"
        "  </config>\n"
        "  <!-- (no <trustedSigners> block) -->\n"
        "</configuration>\n"
        "\n"
        "<!-- The mode looks hardened in review, but with no signer\n"
        "     list NuGet has nothing to validate against, so the\n"
        "     integrity gate the team thinks they enabled is off.\n"
        "-->\n"
        "\n"
        "<!-- Safe: require mode + a populated signer list. -->\n"
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


def _signature_mode(root: ET.Element) -> str | None:
    for child in root:
        if _strip_ns(child.tag) != "config":
            continue
        for entry in child:
            if _strip_ns(entry.tag) != "add":
                continue
            if entry.get("key", "").lower() == "signaturevalidationmode":
                value = entry.get("value", "").strip().lower()
                return value or None
    return None


def _trusted_signers_populated(root: ET.Element) -> bool:
    """True when ``<trustedSigners>`` carries at least one certificate.

    An ``<author>`` / ``<repository>`` with no ``<certificate>`` is
    not a usable trust anchor, so the populated test looks for a
    certificate, not merely a signer element.
    """
    for elem in root.iter():
        if _strip_ns(elem.tag) != "trustedSigners":
            continue
        for descendant in elem.iter():
            if _strip_ns(descendant.tag) == "certificate":
                return True
    return False


def check(cfg: NuGetConfig, ctx: NuGetContext) -> Finding:
    cfg_path = Path(cfg.path)
    if not cfg_path.is_absolute() and ctx.scan_root is not None:
        cfg_path = ctx.scan_root / cfg_path
    try:
        root = ET.parse(str(cfg_path)).getroot()
    except (ET.ParseError, OSError):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description="NuGet.config could not be re-read; nothing to audit.",
            recommendation=RULE.recommendation, passed=True,
        )

    mode = _signature_mode(root)
    if mode != "require":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "signatureValidationMode is not 'require'; trusted-"
                "signer completeness is out of scope here (see "
                "NUGET-012 for the mode itself)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if _trusted_signers_populated(root):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=cfg.path,
            description=(
                "signatureValidationMode=require and <trustedSigners> "
                "lists at least one certificate to validate against."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path,
        description=(
            "signatureValidationMode=require but <trustedSigners> is "
            "missing or has no <certificate>. NuGet has no trust "
            "anchor to validate signatures against, so the require "
            "mode is effectively a no-op and unsigned / untrusted "
            "packages are not actually rejected."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
