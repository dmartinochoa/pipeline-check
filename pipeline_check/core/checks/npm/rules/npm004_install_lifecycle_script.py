"""NPM-004, ``package.json`` declares an install-time lifecycle script."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest

RULE = Rule(
    id="NPM-004",
    title="package.json declares an install-time lifecycle script",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-829",),
    recommendation=(
        "Move the work out of ``preinstall`` / ``install`` / "
        "``postinstall`` / ``prepare`` and into an explicit script "
        "(``\"build\": \"...\"``) invoked at a controlled point in "
        "your pipeline. Install-time scripts run on every consumer's "
        "machine the moment they ``npm install`` your package, with "
        "the consumer's environment (``GH_TOKEN``, ``NPM_TOKEN``, "
        "AWS env, SSH keys). They're also the propagation primitive "
        "the Shai-Hulud worm used to spread across the npm "
        "ecosystem in 2026. If your package legitimately needs "
        "native-module compilation, document it in the README and "
        "expose the build via ``\"build\": \"node-gyp rebuild\"`` so "
        "consumers opt in by calling ``npm run build`` rather than "
        "being opted in by ``npm install``."
    ),
    docs_note=(
        "Fires when ``package.json`` ``scripts`` declares any of:\n\n"
        "* ``preinstall`` — runs before dependencies install\n"
        "* ``install`` — the canonical install hook (rarely needed; "
        "node-gyp triggers this automatically when ``binding.gyp`` "
        "exists, no script needed)\n"
        "* ``postinstall`` — runs after dependencies install; the "
        "Shai-Hulud worm primitive\n"
        "* ``prepare`` — runs on ``npm install`` (no args) and on "
        "``npm publish``; effectively a postinstall for consumers\n\n"
        "This rule guards the *package you're publishing*. To stop "
        "*consumed* dependencies from running their install scripts "
        "during your build, use ``npm ci --ignore-scripts`` (DF-024 "
        "in the Dockerfile pack). Together they cover both sides of "
        "the lifecycle-script attack surface."
    ),
    known_fp=(
        "Packages that wrap a binary release (``esbuild``, ``swc``) "
        "use ``postinstall`` to download the platform-specific "
        "binary. Suppress with a one-line rationale that names the "
        "binary source URL and the integrity check the script "
        "performs. If the script has neither, the package is the "
        "anti-pattern, not the rule.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): the postinstall in compromised "
        "packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, "
        "used the stolen tokens to publish more compromised "
        "packages and push malicious workflow files into victim "
        "repos. Removing the install-time script primitive on the "
        "*publisher* side is the structural fix.",
    ),
    exploit_example=(
        "// Vulnerable: every consumer who runs ``npm install`` on\n"
        "// this package executes ``setup.js`` with THEIR\n"
        "// credentials (``GH_TOKEN``, ``NPM_TOKEN``, AWS env, SSH\n"
        "// keys) silently — they didn't opt into anything beyond\n"
        "// installing the dependency. This is the Shai-Hulud worm\n"
        "// propagation primitive.\n"
        "// package.json\n"
        "{\n"
        "  \"name\": \"my-lib\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"scripts\": {\n"
        "    \"postinstall\": \"node setup.js\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: move the work into an explicit script and document\n"
        "// the opt-in in the README. Consumers who need it run\n"
        "// ``npm run build`` after the install; consumers who don't\n"
        "// pay no cost. If you genuinely need native-module\n"
        "// compilation, ``node-gyp`` triggers ``install`` from a\n"
        "// ``binding.gyp`` without a ``scripts`` entry, so the\n"
        "// scripts block can stay empty.\n"
        "// package.json\n"
        "{\n"
        "  \"name\": \"my-lib\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"scripts\": {\n"
        "    \"build\": \"node setup.js\"\n"
        "  }\n"
        "}"
    ),
)


_INSTALL_LIFECYCLE_SCRIPTS: tuple[str, ...] = (
    "preinstall", "install", "postinstall", "prepare",
)


def check(manifest: NpmManifest) -> Finding:
    scripts = manifest.data.get("scripts")
    if not isinstance(scripts, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="No scripts block declared.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for hook in _INSTALL_LIFECYCLE_SCRIPTS:
        if hook not in scripts:
            continue
        body = scripts.get(hook)
        if not isinstance(body, str) or not body.strip():
            continue
        snippet = body if len(body) <= 60 else body[:57] + "..."
        offenders.append(f"{hook}: {snippet}")
        idx = manifest.text.find(f'"{hook}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "package.json declares no install-time lifecycle scripts."
        if passed else
        f"{len(offenders)} install-time script(s) declared: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Consumers running "
        f"``npm install`` execute these with their own credentials "
        f"(Shai-Hulud propagation pattern)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
