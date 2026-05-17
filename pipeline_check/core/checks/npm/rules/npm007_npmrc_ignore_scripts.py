"""NPM-007, ``.npmrc`` does not declare ``ignore-scripts=true``."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmRc

RULE = Rule(
    id="NPM-007",
    title=".npmrc does not disable install-time lifecycle scripts",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-829",),
    recommendation=(
        "Add ``ignore-scripts=true`` to the repo's ``.npmrc``. The "
        "setting tells npm / pnpm / Yarn 1 to skip every "
        "``preinstall`` / ``install`` / ``postinstall`` / "
        "``prepare`` hook on every transitive dependency, including "
        "the ones added in a future ``npm install``. This is the "
        "file-side complement to DF-024 (which catches the same "
        "primitive at ``docker build`` time) — DF-024 protects the "
        "image, NPM-007 protects the developer laptop and any "
        "unattended CI step running ``npm install`` outside a "
        "container. If a specific package legitimately needs its "
        "build script (a native module like ``better-sqlite3``), "
        "allow-list it after the install: ``npm rebuild "
        "better-sqlite3``."
    ),
    docs_note=(
        "Fires when a ``.npmrc`` exists but does NOT declare "
        "``ignore-scripts=true``. Two failure shapes are flagged:\n\n"
        "* Explicit re-enable: ``ignore-scripts=false`` — someone "
        "  deliberately turned off the protection.\n"
        "* Implicit default: ``ignore-scripts`` not set — npm's "
        "  built-in default is to RUN scripts.\n\n"
        "The rule does NOT fire when no ``.npmrc`` exists in the "
        "scan path; that case is too broad to flag without "
        "generating noise on every JavaScript repo (the npm pack's "
        "DF-024 rule catches the same primitive in the image-build "
        "path, which most production deployments use). To enforce "
        "the rule globally, ship a ``.npmrc`` that declares "
        "``ignore-scripts=true`` and the rule's contract becomes a "
        "ratchet: future commits cannot silently re-enable scripts "
        "without tripping this check.\n\n"
        "Complements NPM-004 (``package.json`` declares its own "
        "install-time hook on the publisher side) and DF-024 "
        "(``RUN npm install`` without ``--ignore-scripts`` at image-"
        "build time). NPM-004 protects consumers of *your* package; "
        "NPM-007 protects *you* from compromised transitive "
        "dependencies on the next install."
    ),
    known_fp=(
        "Repos that build native modules via ``node-gyp`` "
        "(``better-sqlite3``, ``sharp``, ``canvas``, …) need the "
        "lifecycle scripts to compile bindings. The right pattern is "
        "to keep ``ignore-scripts=true`` at the top-level install "
        "and per-package ``npm rebuild <name>`` after, scoped to the "
        "audited native-module set. Suppress only with a one-line "
        "rationale that names the specific binding packages.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the postinstall in compromised "
        "packages scraped credentials and pushed propagation "
        "workflow files. ``ignore-scripts=true`` neutralizes the "
        "postinstall primitive at install time — the worm cannot "
        "execute its first stage if scripts are disabled.",
    ),
    exploit_example=(
        "# Vulnerable: .npmrc carries the npm default (scripts run).\n"
        "# A transitive dep with a malicious postinstall (Shai-Hulud,\n"
        "# TanStack, ua-parser-js 2021) executes with the developer's\n"
        "# or CI runner's environment on the next ``npm install``.\n"
        "registry=https://registry.npmjs.org/\n"
        "# (ignore-scripts not declared — defaults to running scripts)\n"
        "\n"
        "# Safe: explicit ignore-scripts=true. Postinstall on every\n"
        "# dep is suppressed at install time. Native modules that\n"
        "# genuinely need a build (better-sqlite3, sharp) get\n"
        "# rebuilt explicitly after the install:\n"
        "registry=https://registry.npmjs.org/\n"
        "ignore-scripts=true\n"
        "# Then in the install script:\n"
        "#   npm ci\n"
        "#   npm rebuild better-sqlite3 sharp"
    ),
)


_SAFE_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "on"})
_UNSAFE_VALUES: frozenset[str] = frozenset({"false", "0", "no", "off"})


def check(rc: NpmRc) -> Finding:
    raw = rc.settings.get("ignore-scripts")
    if isinstance(raw, str) and raw.strip().lower() in _SAFE_VALUES:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rc.path,
            description=(
                f".npmrc declares ``ignore-scripts={raw.strip()}`` — "
                "install-time lifecycle scripts disabled."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # Best-effort: location at the offending line (if present) or
    # line 1 (rule speaks to the absent / unsafe declaration).
    locations: list[Location] = []
    line_no = 1
    if raw is not None:
        for idx, line in enumerate(rc.text.splitlines(), start=1):
            if "ignore-scripts" in line.lower():
                line_no = idx
                break
    locations.append(Location(
        path=rc.path, start_line=line_no, end_line=line_no,
    ))
    if raw is None:
        desc = (
            ".npmrc does not declare ``ignore-scripts``; npm's "
            "default is to run install-time lifecycle scripts on "
            "every dependency, including transitives. A compromised "
            "package in the tree runs code with the runner's "
            "environment on the next install."
        )
    else:
        normalized = raw.strip().lower()
        kind = "explicitly disabled" if normalized in _UNSAFE_VALUES else (
            f"set to ``{raw.strip()}`` (unrecognized; npm defaults to "
            "running scripts)"
        )
        desc = (
            f".npmrc has ``ignore-scripts`` {kind}. Install-time "
            f"lifecycle scripts run on every dependency, including "
            f"transitives. Compromised-package payloads (Shai-Hulud, "
            f"TanStack, ua-parser-js) execute on the next install."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rc.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
