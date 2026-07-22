"""GHA-065. Workflow body contains zero-width / bidi Unicode.

The Trojan-Source class (Boucher & Anderson, 2021). An attacker
inserts invisible Unicode characters (zero-width joiners,
right-to-left overrides, bidi isolates) into a string literal in
the YAML. The PR diff renders one expression on screen; the YAML
parser sees a different stream of bytes. The author and the
reviewer can't tell anything is wrong because their editors hide
the chars or render them as their visual-only effects.

These characters carry no syntactic meaning in a CI workflow.
Any occurrence inside a workflow value is steganographic by
nature, the workflow doesn't need them and they only exist to
hide intent from a human reviewer.

The fix: strip them. ``LC_ALL=C tr -d '[:cntrl:]' < workflow.yml``
removes the offending bytes; ``rg --no-pcre2 '[\\x{200E}\\x{200F}
\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{FEFF}]' .github/`` finds
them. Reject any PR whose diff introduces them.
"""
from __future__ import annotations

from typing import Any

from ...base import Confidence, Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-065",
    title="Workflow body contains zero-width or bidi Unicode characters",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-6"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-1007",),  # Insufficient Visual Distinction of Homoglyphs
    recommendation=(
        "Strip zero-width and bidi characters from the workflow. "
        "Then enforce a PR check that rejects any newly-introduced "
        "occurrence: ``rg --no-pcre2 '[\\x{200B}-\\x{200F}\\x{202A}-"
        "\\x{202E}\\x{2066}-\\x{2069}\\x{FEFF}]' .github/`` should "
        "match no files. CI workflows don't need any of these "
        "characters for legitimate purposes."
    ),
    docs_note=(
        "Walks every string value in the parsed workflow document "
        "(``run:`` bodies, ``with:`` values, ``env:`` values, "
        "``if:`` expressions, etc.) for any of the following "
        "Unicode codepoints:\n\n"
        "* **Zero-width:** ``U+200B`` (zero-width space), "
        "``U+200C`` (zero-width non-joiner), ``U+200D`` "
        "(zero-width joiner), ``U+FEFF`` (zero-width no-break "
        "space / BOM).\n"
        "* **Bidi controls:** ``U+200E`` (LRM), ``U+200F`` "
        "(RLM), ``U+202A``-``U+202E`` (LRE / RLE / PDF / LRO / "
        "RLO), ``U+2066``-``U+2069`` (LRI / RLI / FSI / PDI).\n\n"
        "Any single occurrence fires the rule. Reports the "
        "containing key path and codepoint count so the offender "
        "can be located in a possibly-large body. The rule is "
        "deliberately strict: no carve-out for ``# UTF-8 BOM`` "
        "at the start of the file (a BOM in YAML is treated as "
        "an opaque character by every parser; reject it). No "
        "carve-out for ``zero-width joiner`` in a comment "
        "because comments aren't preserved through PyYAML "
        "parsing, the visible string values are."
    ),
    known_fp=(
        "Workflows that legitimately echo internationalized text "
        "in a release-notes pipeline. Audit each occurrence; "
        "almost every case is unintentional or actively "
        "malicious. Suppress per-step via ignore-file when the "
        "presence is documented and the surrounding code has been "
        "reviewed against the visual-vs-parsed shape question.",
    ),
    incident_refs=(
        "Boucher & Anderson, ``Trojan Source: Invisible "
        "Vulnerabilities`` (2021): "
        "https://trojansource.codes/",
        "zizmor proposal #914 (workflow-bidi-unicode audit): "
        "https://github.com/zizmorcore/zizmor/issues/914",
    ),
    exploit_example=(
        "# Vulnerable: the workflow body contains an invisible\n"
        "# right-to-left override (U+202E) and a first-strong\n"
        "# isolate (U+2066). A diff viewer renders the run line\n"
        "# as ``echo harmless`` but the YAML parser sees the\n"
        "# embedded bidi controls, and the shell receives a\n"
        "# different command after the controls reorder the\n"
        "# token stream during display.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      # The string below holds U+202E and U+2066 between\n"
        "      # ``override`` and ``--harmless``. Render in a\n"
        "      # bidi-aware terminal to see the camouflage.\n"
        "      - run: bash override\\u202E\\u2066--harmless\\u2069\\u2066\n"
        "\n"
        "# Safe: the same workflow with the bidi controls\n"
        "# stripped. The visible characters now match what the\n"
        "# parser sees.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: bash override --harmless"
    ),
)

#: Suspicious codepoints. Bidi controls + zero-width chars + BOM.
#: Each appears as an individual char in any flagged string, so a
#: cheap ``any(c in s for c in _SUSPICIOUS)`` check per string is
#: sufficient to find the offender.
_SUSPICIOUS: frozenset[str] = frozenset(
    chr(cp) for cp in (
        # Zero-width family
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        # Bidi controls
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    )
)


def _scan_value(value: Any, key_path: str, hits: list[str]) -> None:
    """Recursively walk *value* recording each suspicious codepoint hit.

    Strings are scanned directly. Mappings and sequences recurse with
    an extended ``key_path`` that the rule's description renders.
    Non-string scalars (int / bool / None) are skipped.
    """
    if isinstance(value, str):
        codepoints = [hex(ord(c)) for c in value if c in _SUSPICIOUS]
        if codepoints:
            preview = ", ".join(codepoints[:3])
            suffix = "..." if len(codepoints) > 3 else ""
            hits.append(f"{key_path} ({preview}{suffix})")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            child = f"{key_path}.{k}" if key_path else str(k)
            # A zero-width / bidi char smuggled into a key (an env var
            # name, job id, or with-input name) is the same Trojan-Source
            # shape, so scan the key string itself, not just its value.
            if isinstance(k, str):
                key_cps = [hex(ord(c)) for c in k if c in _SUSPICIOUS]
                if key_cps:
                    preview = ", ".join(key_cps[:3])
                    suffix = "..." if len(key_cps) > 3 else ""
                    hits.append(f"{child} (key) ({preview}{suffix})")
            _scan_value(v, child, hits)
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            child = f"{key_path}[{idx}]"
            _scan_value(item, child, hits)
        return


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits: list[str] = []
    _scan_value(doc, "", hits)
    passed = not hits
    desc = (
        "No zero-width or bidi Unicode characters in the workflow body."
        if passed else
        f"{len(hits)} workflow value(s) contain zero-width or bidi "
        f"Unicode: {'; '.join(hits[:3])}"
        f"{'...' if len(hits) > 3 else ''}. These characters carry "
        f"no syntactic meaning in CI workflows; their presence is "
        f"steganographic. Diff viewers render one expression while "
        f"the YAML parser sees another."
    )
    f = Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        confidence=Confidence.HIGH,
    )
    # Lock confidence: the presence of a bidi/zero-width char is
    # unambiguous, no need for the default heuristic demotion.
    f.confidence_locked = True
    return f
